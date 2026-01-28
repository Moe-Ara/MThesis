import json
from typing import Any, Dict, Optional

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from intelligence.core.base import Scorer
from intelligence.core.utils import extract_json


def _build_scorer_prompt(alert: Dict[str, Any]) -> str:
    return (
        "You are a SOC threat scoring assistant. "
        "Return JSON with fields: severity (0-100 int), confidence (0-1 float), "
        "hypothesis (string), evidence (array of strings). "
        "Be concise and deterministic.\n\n"
        f"Alert:\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n"
    )


class LocalModelScorer(Scorer):
    def __init__(self, base_model: str, adapter_path: Optional[str], max_new_tokens: int, temperature: float):
        self.base_model = base_model
        self.adapter_path = adapter_path
        self.max_new_tokens = max_new_tokens
        self.temperature = temperature
        self._tokenizer = None
        self._model = None
        self._load()

    def _load(self) -> None:
        dtype = torch.float16 if torch.cuda.is_available() else torch.float32
        tokenizer = AutoTokenizer.from_pretrained(self.base_model, use_fast=True)
        tokenizer.pad_token = tokenizer.eos_token
        model = AutoModelForCausalLM.from_pretrained(
            self.base_model,
            torch_dtype=dtype,
            device_map="auto" if torch.cuda.is_available() else None,
            trust_remote_code=True,
        )
        if self.adapter_path:
            model = PeftModel.from_pretrained(model, self.adapter_path)
        model.eval()
        self._tokenizer = tokenizer
        self._model = model

    def score(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        tokenizer = self._tokenizer
        model = self._model
        if tokenizer is None or model is None:
            return None
        prompt = _build_scorer_prompt(alert)
        inputs = tokenizer(prompt, return_tensors="pt", truncation=True)
        device = next(model.parameters()).device
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with torch.inference_mode():
            outputs = model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                pad_token_id=tokenizer.eos_token_id,
                eos_token_id=tokenizer.eos_token_id,
                do_sample=True,
                temperature=self.temperature,
            )
        generated = outputs[0][inputs["input_ids"].shape[-1] :]
        completion = tokenizer.decode(generated, skip_special_tokens=True).strip()
        return extract_json(completion)
