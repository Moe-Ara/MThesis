import argparse
import logging
from pathlib import Path
from typing import Dict

import torch
from datasets import load_dataset
from peft import LoraConfig, TaskType, get_peft_model, prepare_model_for_kbit_training
from torch.utils.data import Dataset
from transformers import (AutoConfig, AutoModelForCausalLM, AutoTokenizer, DataCollatorForLanguageModeling,
                          Trainer, TrainingArguments)


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class JsonlPromptDataset(Dataset):
    def __init__(self, dataset, tokenizer, max_length: int):
        self.dataset = dataset
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.dataset)

    def _build_text(self, example: Dict) -> str:
        prompt = example.get("prompt") or example.get("detection_goal") or ""
        completion = example.get("completion") or example.get("response") or ""
        prompt = prompt.strip()
        completion = completion.strip()
        if not prompt:
            return completion
        if not completion:
            return prompt
        return f"{prompt}\n\n{completion}"

    def __getitem__(self, idx: int) -> Dict:
        example = self.dataset[idx]
        text = self._build_text(example)
        tokenized = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt",
        )
        tokenized = {k: v.squeeze(0) for k, v in tokenized.items()}
        tokenized["labels"] = tokenized["input_ids"].clone()
        return tokenized


def create_lora_model(model_name: str, lora_rank: int) -> AutoModelForCausalLM:
    model_path = Path(model_name)
    tokenizer_kwargs: Dict[str, str] = {"padding_side": "right", "use_fast": True}
    tokenizer_file = model_path / "tokenizer.model.v3"
    tokenizer_config = model_path / "tokenizer_config.json"
    if tokenizer_file.exists():
        tokenizer_kwargs["tokenizer_file"] = str(tokenizer_file)
    if tokenizer_config.exists():
        tokenizer_kwargs["tokenizer_config"] = str(tokenizer_config)

    try:
        tokenizer = AutoTokenizer.from_pretrained(model_name, **tokenizer_kwargs)
    except Exception as exc:
        logging.getLogger(__name__).warning(
            "Fast tokenizer failed (%s). Retrying with slow tokenizer.", exc
        )
        tokenizer_kwargs["use_fast"] = False
        tokenizer = AutoTokenizer.from_pretrained(model_name, **tokenizer_kwargs)
    tokenizer.pad_token = tokenizer.eos_token
    config_path = model_path / "config.json"
    config_source = str(config_path) if config_path.exists() else model_name
    config = AutoConfig.from_pretrained(config_source)
    model_source = str(model_path) if model_path.exists() else model_name
    model = AutoModelForCausalLM.from_pretrained(
        model_source,
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
        device_map="auto" if torch.cuda.is_available() else None,
        config=config,
    )

    model = prepare_model_for_kbit_training(model)
    peft_config = LoraConfig(
        r=lora_rank,
        lora_alpha=32,
        target_modules=["q_proj", "v_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type=TaskType.CAUSAL_LM,
    )
    model = get_peft_model(model, peft_config)
    return model, tokenizer


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune a Lora-adapted Mistral model.")
    parser.add_argument(
        "--model",
        default="mistralai/mistral-7b",
        help="Hugging Face model identifier to fine-tune.",
    )
    parser.add_argument(
        "--data",
        type=Path,
        default=Path("training_data.jsonl"),
        help="JSONL file with prompt/completion entries.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("wazuh-specialized"),
        help="Output directory for the fine-tuned adapter.",
    )
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs.")
    parser.add_argument("--batch-size", type=int, default=1, help="Per device batch size.")
    parser.add_argument("--lr", type=float, default=2e-4, help="Learning rate.")
    parser.add_argument("--lora-rank", type=int, default=8, help="LoRA rank.")
    parser.add_argument("--max-length", type=int, default=512, help="Tokenization max length.")
    parser.add_argument("--gradient-accumulation-steps", type=int, default=16)

    args = parser.parse_args()

    if not torch.cuda.is_available():
        logger.warning(
            "CUDA is not available; training will run on CPU which may be very slow. "
            "Ensure CUDA drivers and a compatible GPU are installed for acceptable training times."
        )
    dataset = load_dataset("json", data_files=str(args.data))["train"]

    model, tokenizer = create_lora_model(args.model, args.lora_rank)
    train_dataset = JsonlPromptDataset(dataset, tokenizer, args.max_length)

    data_collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)
    training_args = TrainingArguments(
        output_dir=str(args.output),
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        learning_rate=args.lr,
        num_train_epochs=args.epochs,
        logging_steps=10,
        save_total_limit=2,
        fp16=torch.cuda.is_available(),
        save_strategy="epoch",
        warmup_ratio=0.1,
        remove_unused_columns=False,
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
