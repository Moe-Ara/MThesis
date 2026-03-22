"""
LoRA fine-tuning script for Foundation-Sec-8B on SOAR scoring/planning tasks.

Usage:
    # Fine-tune scorer
    python -m intelligence.training.train_soar \
        --task scorer \
        --data intelligence/training/data/scorer_train.jsonl \
        --output models/foundation-sec-scorer-lora

    # Fine-tune planner
    python -m intelligence.training.train_soar \
        --task planner \
        --data intelligence/training/data/planner_train.jsonl \
        --output models/foundation-sec-planner-lora

Requires: ~12-14 GB VRAM with default settings (RTX 5070 Ti 16GB is sufficient).
"""

import argparse
import logging
from pathlib import Path
from typing import Dict

import torch
from datasets import load_dataset
from peft import LoraConfig, TaskType, get_peft_model, prepare_model_for_kbit_training
from torch.utils.data import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    DataCollatorForLanguageModeling,
    Trainer,
    TrainingArguments,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BASE_MODEL = "fdtn-ai/Foundation-Sec-8B"


class SoarDataset(Dataset):
    """Instruction-tuning dataset using Llama 3.1 chat template."""

    def __init__(self, dataset, tokenizer, max_length: int, task: str):
        self.dataset = dataset
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.task = task

    def __len__(self):
        return len(self.dataset)

    def _build_text(self, example: Dict) -> str:
        prompt = example.get("prompt", "")
        completion = example.get("completion", "")

        system_msg = (
            "You are a cybersecurity SOC analyst assistant. "
            "You respond only with valid JSON matching the requested schema."
        )

        # Llama 3.1 Instruct chat format
        text = (
            f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
            f"{system_msg}<|eot_id|>"
            f"<|start_header_id|>user<|end_header_id|>\n\n"
            f"{prompt}<|eot_id|>"
            f"<|start_header_id|>assistant<|end_header_id|>\n\n"
            f"{completion}<|eot_id|>"
        )
        return text

    def __getitem__(self, idx: int) -> Dict:
        example = self.dataset[idx]
        text = self._build_text(example)
        tokenized = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt",
        )
        tokenized = {k: v.squeeze(0) for k, v in tokenized.items()}
        tokenized["labels"] = tokenized["input_ids"].clone()
        # Mask padding tokens in labels
        tokenized["labels"][tokenized["labels"] == self.tokenizer.pad_token_id] = -100
        return tokenized


def create_model_and_tokenizer(model_name: str, lora_rank: int, use_4bit: bool = True):
    """Load Foundation-Sec-8B with optional 4-bit quantization and LoRA."""

    tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    if use_4bit and torch.cuda.is_available():
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            quantization_config=bnb_config,
            device_map="auto",
            torch_dtype=torch.bfloat16,
        )
        model = prepare_model_for_kbit_training(model)
    else:
        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
            device_map="auto" if torch.cuda.is_available() else None,
        )

    # LoRA config targeting attention layers (Llama 3.1 architecture)
    peft_config = LoraConfig(
        r=lora_rank,
        lora_alpha=lora_rank * 2,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type=TaskType.CAUSAL_LM,
    )
    model = get_peft_model(model, peft_config)

    trainable, total = 0, 0
    for _, p in model.named_parameters():
        total += p.numel()
        if p.requires_grad:
            trainable += p.numel()
    logger.info(f"Trainable parameters: {trainable:,} / {total:,} ({100*trainable/total:.2f}%)")

    return model, tokenizer


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune Foundation-Sec-8B for SOAR tasks.")
    parser.add_argument("--task", choices=["scorer", "planner"], required=True)
    parser.add_argument("--model", default=BASE_MODEL, help="Base model to fine-tune.")
    parser.add_argument("--data", type=Path, required=True, help="JSONL training data.")
    parser.add_argument("--output", type=Path, required=True, help="Output directory for LoRA adapter.")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=2)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=8)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--lora-rank", type=int, default=16)
    parser.add_argument("--max-length", type=int, default=2048)
    parser.add_argument("--no-4bit", action="store_true", help="Disable 4-bit quantization.")
    args = parser.parse_args()

    if not args.data.exists():
        raise FileNotFoundError(f"Training data not found: {args.data}")

    logger.info(f"Task: {args.task}")
    logger.info(f"Base model: {args.model}")
    logger.info(f"Training data: {args.data}")
    logger.info(f"Output: {args.output}")
    logger.info(f"GPU: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'}")

    dataset = load_dataset("json", data_files=str(args.data))["train"]
    logger.info(f"Loaded {len(dataset)} training examples.")

    model, tokenizer = create_model_and_tokenizer(args.model, args.lora_rank, use_4bit=not args.no_4bit)
    train_dataset = SoarDataset(dataset, tokenizer, args.max_length, args.task)

    training_args = TrainingArguments(
        output_dir=str(args.output),
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        learning_rate=args.lr,
        num_train_epochs=args.epochs,
        logging_steps=10,
        save_strategy="epoch",
        save_total_limit=2,
        fp16=False,
        bf16=torch.cuda.is_available(),
        warmup_ratio=0.1,
        weight_decay=0.01,
        remove_unused_columns=False,
        report_to="none",
        dataloader_pin_memory=False,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        data_collator=DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False),
    )

    logger.info("Starting training...")
    trainer.train()

    logger.info(f"Saving LoRA adapter to {args.output}")
    model.save_pretrained(args.output)
    tokenizer.save_pretrained(args.output)
    logger.info("Done.")


if __name__ == "__main__":
    main()
