import argparse
import logging
import math
import time
from pathlib import Path

from datasets import load_dataset
import torch
from transformers import (
    AutoModelForSeq2SeqLM,
    AutoTokenizer,
    DataCollatorForSeq2Seq,
    Seq2SeqTrainer,
    Seq2SeqTrainingArguments,
    TrainerCallback,
    set_seed,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


class TimeEstimateCallback(TrainerCallback):
    def __init__(self, total_steps: int, log_every: int) -> None:
        self.total_steps = max(1, total_steps)
        self.log_every = max(1, log_every)
        self.start_time: float | None = None

    def on_train_begin(self, args, state, control, **kwargs):
        self.start_time = time.time()

    def on_step_end(self, args, state, control, **kwargs):
        if self.start_time is None or state.global_step <= 0:
            return
        if state.global_step % self.log_every != 0:
            return
        elapsed = time.time() - self.start_time
        rate = state.global_step / elapsed if elapsed > 0 else 0.0
        remaining = (self.total_steps - state.global_step) / rate if rate > 0 else 0.0
        pct = min(100.0, 100.0 * state.global_step / self.total_steps)
        logger.info(
            "Progress: step %s/%s (%.1f%%) - elapsed %s - eta %s",
            state.global_step,
            self.total_steps,
            pct,
            _format_duration(elapsed),
            _format_duration(remaining),
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune a seq2seq planner model.")
    parser.add_argument(
        "--data",
        type=Path,
        default=Path("intelligence/training/data/planner_seq2seq_train_canonical.jsonl"),
        help="JSONL planner training data.",
    )
    parser.add_argument(
        "--model",
        default="google/flan-t5-base",
        help="Base seq2seq model ID or local path.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("intelligence/models/planner_seq2seq"),
        help="Output directory for the fine-tuned model.",
    )
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=4)
    parser.add_argument("--learning-rate", type=float, default=3e-4)
    parser.add_argument("--max-source-length", type=int, default=1024)
    parser.add_argument("--max-target-length", type=int, default=512)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--gradient-checkpointing", action="store_true")
    parser.add_argument("--no-fp16", action="store_true", help="Disable fp16 even if CUDA is available.")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of training examples (0 = all).")
    parser.add_argument("--max-steps", type=int, default=0, help="Cap total training steps (0 = no cap).")
    parser.add_argument("--logging-steps", type=int, default=10, help="Log every N optimizer steps.")
    parser.add_argument("--disable-tqdm", action="store_true", help="Disable progress bars.")
    args = parser.parse_args()

    if not args.data.exists():
        raise FileNotFoundError(f"Training data not found: {args.data}")

    set_seed(args.seed)
    logger.info("Loading dataset from %s", args.data)
    dataset = load_dataset("json", data_files=str(args.data))["train"]
    if args.limit and args.limit > 0:
        dataset = dataset.shuffle(seed=args.seed).select(range(min(args.limit, len(dataset))))
    splits = dataset.train_test_split(test_size=0.1, seed=args.seed)
    train_count = len(splits["train"])
    steps_per_epoch = math.ceil(train_count / (args.batch_size * args.gradient_accumulation_steps))
    total_steps = (
        args.max_steps if args.max_steps > 0 else steps_per_epoch * args.epochs
    )
    logger.info("Training examples: %s (steps/epoch=%s, total_steps=%s)", train_count, steps_per_epoch, total_steps)

    cuda_available = torch.cuda.is_available()
    if cuda_available:
        device_name = torch.cuda.get_device_name(0)
        logger.info("CUDA available: True (%s)", device_name)
    else:
        logger.info("CUDA available: False (CPU mode)")

    tokenizer = AutoTokenizer.from_pretrained(args.model, use_fast=True)
    model = AutoModelForSeq2SeqLM.from_pretrained(args.model)

    def preprocess(batch):
        inputs = tokenizer(
            batch["prompt"],
            max_length=args.max_source_length,
            truncation=True,
        )
        labels = tokenizer(
            text_target=batch["completion"],
            max_length=args.max_target_length,
            truncation=True,
        )
        inputs["labels"] = labels["input_ids"]
        return inputs

    logger.info("Tokenizing dataset...")
    tokenized = splits.map(preprocess, batched=True, remove_columns=splits["train"].column_names)
    logger.info("Tokenization complete.")
    data_collator = DataCollatorForSeq2Seq(tokenizer, model=model)

    training_args = Seq2SeqTrainingArguments(
        output_dir=str(args.output),
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        learning_rate=args.learning_rate,
        num_train_epochs=args.epochs,
        max_steps=args.max_steps if args.max_steps > 0 else -1,
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=2,
        predict_with_generate=False,
        logging_steps=args.logging_steps,
        report_to="none",
        fp16=False,
        bf16=(cuda_available and not args.no_fp16),
        gradient_checkpointing=args.gradient_checkpointing,
        disable_tqdm=args.disable_tqdm,
    )

    callbacks = [TimeEstimateCallback(total_steps=total_steps, log_every=args.logging_steps)]
    trainer = Seq2SeqTrainer(
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["test"],
        data_collator=data_collator,
        callbacks=callbacks,
    )

    logger.info("Starting seq2seq planner fine-tuning...")
    trainer.train()

    logger.info("Saving model to %s", args.output)
    trainer.save_model(str(args.output))
    tokenizer.save_pretrained(str(args.output))


if __name__ == "__main__":
    main()
