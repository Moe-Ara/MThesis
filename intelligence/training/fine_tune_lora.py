from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Dict, List

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
logging.basicConfig(level=logging.INFO)


class JsonlPromptDataset(Dataset):
    def __init__(self, dataset, tokenizer, max_length: int, system_prompt: str | None = None):
        self.dataset = dataset
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.system_prompt = system_prompt

    def __len__(self) -> int:
        return len(self.dataset)

    def _build_text(self, example: Dict) -> str:
        messages = example.get("messages")
        if isinstance(messages, list) and messages:
            if self.system_prompt:
                messages = [{"role": "system", "content": self.system_prompt}] + messages
            if hasattr(self.tokenizer, "apply_chat_template"):
                return self.tokenizer.apply_chat_template(
                    messages,
                    tokenize=False,
                    add_generation_prompt=False,
                )
            return "\n".join([f"{msg.get('role')}: {msg.get('content')}" for msg in messages])

        prompt = (
            example.get("prompt")
            or example.get("instruction")
            or example.get("input")
            or example.get("detection_goal")
            or ""
        )
        completion = (
            example.get("completion")
            or example.get("response")
            or example.get("output")
            or example.get("plan")
            or ""
        )

        prompt = str(prompt).strip()
        completion = str(completion).strip()

        if self.system_prompt:
            if prompt:
                prompt = f"{self.system_prompt}\n\n{prompt}"
            else:
                prompt = self.system_prompt

        if prompt and completion:
            return f"{prompt}\n\n{completion}"
        if prompt:
            return prompt
        if completion:
            return completion
        return json.dumps(example)

    def __getitem__(self, idx: int) -> Dict:
        example = self.dataset[idx]
        text = self._build_text(example)
        tokenized = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_length,
        )
        tokenized["labels"] = tokenized["input_ids"].copy()
        return tokenized


def _parse_target_modules(value: str) -> List[str]:
    if not value:
        return ["q_proj", "v_proj"]
    return [item.strip() for item in value.split(",") if item.strip()]


def _load_model(
    model_id: str,
    quantization: str,
    bf16: bool,
    trust_remote_code: bool,
    use_gradient_checkpointing: bool,
) -> AutoModelForCausalLM:
    torch_dtype = torch.bfloat16 if bf16 else torch.float16
    device_map = "auto" if torch.cuda.is_available() else None

    if quantization == "none":
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch_dtype,
            device_map=device_map,
            trust_remote_code=trust_remote_code,
        )
    else:
        try:
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=quantization == "4bit",
                load_in_8bit=quantization == "8bit",
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch_dtype,
            )
        except Exception as exc:
            raise RuntimeError(
                "BitsAndBytesConfig is unavailable. Install bitsandbytes or use --quantization none."
            ) from exc

        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            quantization_config=bnb_config,
            device_map=device_map,
            trust_remote_code=trust_remote_code,
        )
        model = prepare_model_for_kbit_training(model)

    if use_gradient_checkpointing:
        model.gradient_checkpointing_enable()
        model.config.use_cache = False

    return model


def _print_trainable_parameters(model) -> None:
    trainable = 0
    total = 0
    for _, param in model.named_parameters():
        total += param.numel()
        if param.requires_grad:
            trainable += param.numel()
    ratio = (trainable / total) if total else 0.0
    logger.info("Trainable params: %s / %s (%.2f%%)", trainable, total, ratio * 100)


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune a model with LoRA adapters.")
    parser.add_argument("--model", required=True, help="Hugging Face model ID or local path.")
    parser.add_argument("--data", type=Path, required=True, help="JSONL training data file.")
    parser.add_argument("--output", type=Path, default=Path("intelligence/adapters/baronllm"))
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--lora-r", type=int, default=8)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--lora-dropout", type=float, default=0.05)
    parser.add_argument("--max-length", type=int, default=768)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=16)
    parser.add_argument("--quantization", choices=["none", "4bit", "8bit"], default="4bit")
    parser.add_argument("--bf16", action="store_true")
    parser.add_argument("--fp16", action="store_true")
    parser.add_argument("--trust-remote-code", action="store_true")
    parser.add_argument("--target-modules", default="q_proj,v_proj")
    parser.add_argument("--system-prompt", default=None)
    parser.add_argument("--save-total-limit", type=int, default=2)
    parser.add_argument("--use-gradient-checkpointing", action="store_true")

    args = parser.parse_args()

    if not args.data.exists():
        raise FileNotFoundError(f"Training data not found: {args.data}")

    if args.quantization != "none" and not torch.cuda.is_available():
        logger.warning("Quantization requested without CUDA. Training may fail or be slow.")

    dataset = load_dataset("json", data_files=str(args.data))
    train_dataset = dataset["train"]

    tokenizer = AutoTokenizer.from_pretrained(
        args.model,
        padding_side="right",
        trust_remote_code=args.trust_remote_code,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = _load_model(
        args.model,
        quantization=args.quantization,
        bf16=args.bf16,
        trust_remote_code=args.trust_remote_code,
        use_gradient_checkpointing=args.use_gradient_checkpointing,
    )

    target_modules = _parse_target_modules(args.target_modules)
    peft_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        target_modules=target_modules,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type=TaskType.CAUSAL_LM,
    )
    model = get_peft_model(model, peft_config)
    _print_trainable_parameters(model)

    train_dataset = JsonlPromptDataset(
        train_dataset,
        tokenizer,
        max_length=args.max_length,
        system_prompt=args.system_prompt,
    )

    data_collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)

    training_args = TrainingArguments(
        output_dir=str(args.output),
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        learning_rate=args.lr,
        num_train_epochs=args.epochs,
        logging_steps=10,
        save_total_limit=args.save_total_limit,
        save_strategy="epoch",
        warmup_ratio=0.1,
        remove_unused_columns=False,
        fp16=args.fp16,
        bf16=args.bf16,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        data_collator=data_collator,
    )

    trainer.train()
    model.save_pretrained(args.output)
    tokenizer.save_pretrained(args.output)


if __name__ == "__main__":
    main()
