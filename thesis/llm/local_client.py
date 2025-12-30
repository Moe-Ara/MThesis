"""Local transformer-based LLM client backed by Hugging Face + PEFT adapters."""

import json
from pathlib import Path
from typing import Any, Dict

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from thesis.llm.base import LlmClient


class LocalTransformerClient(LlmClient):
    """Wraps a PEFT adapter + base model so we can answer prompts offline."""

    def __init__(
        self,
        adapter_path: Path,
        base_model: str,
        max_new_tokens: int = 512,
        temperature: float = 0.3,
    ) -> None:
        self.adapter_path = Path(adapter_path)
        self.max_new_tokens = max_new_tokens
        self.temperature = temperature
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.adapter_path, padding_side="right", use_fast=True
        )
        self.tokenizer.pad_token = self.tokenizer.eos_token
        self.model = self._load_model(base_model)
        self.model.eval()

    def _load_model(self, base_model: str):
        dtype = torch.float16 if torch.cuda.is_available() else torch.float32
        base = AutoModelForCausalLM.from_pretrained(
            base_model,
            torch_dtype=dtype,
            device_map="auto" if torch.cuda.is_available() else None,
            trust_remote_code=True,
        )
        return PeftModel.from_pretrained(base, self.adapter_path)

    def generate(
        self,
        system_prompt: str,
        user_payload: Dict[str, Any],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        prompt = self._build_prompt(system_prompt, user_payload)
        inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True)
        model_device = next(self.model.parameters()).device
        inputs = {k: v.to(model_device) for k, v in inputs.items()}
        with torch.inference_mode():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                pad_token_id=self.tokenizer.eos_token_id,
                eos_token_id=self.tokenizer.eos_token_id,
                do_sample=True,
                temperature=self.temperature,
            )
        generated = outputs[0][inputs["input_ids"].shape[-1] :]
        completion = self.tokenizer.decode(generated, skip_special_tokens=True).strip()
        return self._deserialize_response(completion)

    @staticmethod
    def _build_prompt(system_prompt: str, payload: Dict[str, Any]) -> str:
        payload_json = json.dumps(payload, indent=2, sort_keys=True)
        return (
            f"{system_prompt.strip()}\n\n"
            f"User payload:\n{payload_json}\n\n"
            "Respond ONLY with a single JSON object matching the schema described above."
        )

    @staticmethod
    def _deserialize_response(text: str) -> Dict[str, Any]:
        snippet = text.strip()
        if not snippet:
            return {"message": ""}
        start = snippet.find("{")
        end = snippet.rfind("}")
        if start == -1 or end == -1:
            return {"message": snippet}
        candidate = snippet[start : end + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            return {"message": snippet}
