from typing import Any, Dict

import torch
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

from intelligence.core.base import Planner
from intelligence.core.utils import extract_json, repair_json
from intelligence.planners.plan_utils import sanitize_plan
from intelligence.planners.prompting import build_planner_prompt_seq2seq
from intelligence.planners.rule import RulePlanner
from intelligence.training.build_planner_seq2seq_dataset import parse_pipe_completion


class Seq2SeqPlanner(Planner):
    def __init__(
        self,
        model_path: str,
        max_new_tokens: int = 384,
        num_beams: int = 4,
        temperature: float = 0.0,
        max_source_length: int = 512,
    ):
        self.model_path = model_path
        self.max_new_tokens = max_new_tokens
        self.num_beams = num_beams
        self.temperature = temperature
        self.max_source_length = max_source_length
        self._tokenizer = None
        self._model = None
        self._load()

    def _load(self) -> None:
        dtype = torch.bfloat16 if torch.cuda.is_available() else torch.float32
        tokenizer = AutoTokenizer.from_pretrained(self.model_path, use_fast=True)
        model = AutoModelForSeq2SeqLM.from_pretrained(
            self.model_path,
            torch_dtype=dtype,
            device_map="auto" if torch.cuda.is_available() else None,
        )
        model.eval()
        self._tokenizer = tokenizer
        self._model = model

    def _generate(self, prompt: str) -> str:
        """Tokenize prompt and generate completion text."""
        inputs = self._tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=self.max_source_length,
        )
        device = next(self._model.parameters()).device
        inputs = {k: v.to(device) for k, v in inputs.items()}
        generate_kwargs = {
            "max_new_tokens": self.max_new_tokens,
            "num_beams": self.num_beams,
            "do_sample": self.temperature > 0.0,
            "pad_token_id": self._tokenizer.eos_token_id,
        }
        if self.temperature > 0.0:
            generate_kwargs["temperature"] = self.temperature
        with torch.inference_mode():
            outputs = self._model.generate(**inputs, **generate_kwargs)
        return self._tokenizer.decode(outputs[0], skip_special_tokens=True).strip()

    def _parse_output(self, completion: str) -> Dict[str, Any] | None:
        """Try pipe format first, then JSON fallback."""
        if "|" in completion and "strategy=" in completion:
            return parse_pipe_completion(completion)
        parsed = extract_json(completion) or repair_json(completion)
        if not parsed:
            wrapped = "{" + completion.strip().strip(",") + "}"
            parsed = extract_json(wrapped) or repair_json(wrapped)
        return parsed

    def plan(self, alert: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
        if not self._tokenizer or not self._model:
            raise RuntimeError("Seq2Seq planner model not loaded.")
        prompt = build_planner_prompt_seq2seq(alert, assessment)
        completion = self._generate(prompt)
        parsed = self._parse_output(completion)
        if not parsed:
            return RulePlanner().plan(alert, assessment)
        return sanitize_plan(parsed, alert, assessment, derive_strategy_from_actions=True)

    def plan_from_prompt(self, prompt: str) -> Dict[str, Any]:
        """Run inference directly from a pre-built prompt string (used by eval)."""
        if not self._tokenizer or not self._model:
            raise RuntimeError("Seq2Seq planner model not loaded.")
        completion = self._generate(prompt)
        return self._parse_output(completion) or {}
