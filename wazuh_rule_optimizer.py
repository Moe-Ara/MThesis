import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

from thesis.llm.client import OllamaLlmClient
from wazuh_rule_agent import WazuhRuleAgent


class LocalLlmClient:
    def __init__(
        self,
        adapter_path: Path,
        base_model: str,
        max_response_tokens: int = 512,
        temperature: float = 0.3,
    ):
        self.adapter_path = Path(adapter_path)
        self.max_response_tokens = max_response_tokens
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
        from peft import PeftModel

        return PeftModel.from_pretrained(base, self.adapter_path)

    def generate(self, system_prompt: str, user_payload: Dict[str, Any]) -> Dict[str, Any]:
        prompt = self._build_prompt(system_prompt, user_payload)
        inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True)
        model_device = next(self.model.parameters()).device
        inputs = {k: v.to(model_device) for k, v in inputs.items()}
        with torch.inference_mode():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=self.max_response_tokens,
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


class WazuhRuleOptimizer:
    def __init__(self, llm_client: Any):
        self.agent = WazuhRuleAgent(llm_client)

    def optimize_from_files(
        self,
        detection_goal: str,
        rules_path: Path,
        logs_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        rules_xml = rules_path.read_text(encoding="utf-8")
        logs = self._load_logs(logs_path) if logs_path else []

        payload = {
            "detection_goal": detection_goal,
            "existing_rules_xml": rules_xml,
            "example_events": logs,
            "existing_logs": logs,
        }
        return self.agent.create_rule(**payload)

    @staticmethod
    def _load_logs(path: Path) -> List[Dict[str, Any]]:
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            return []

        data = json.loads(raw)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        raise ValueError("Log file must contain a JSON object or array.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Optimize Wazuh rules using example logs and an Ollama agent or a local model."
    )
    parser.add_argument(
        "--detection-goal",
        required=True,
        help="High-level description of what the rule should detect.",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        required=True,
        help="Path to the existing Wazuh rules XML file.",
    )
    parser.add_argument(
        "--logs",
        type=Path,
        help="Optional path to a JSON file containing sample logs.",
    )
    parser.add_argument(
        "--mode",
        choices=["online", "offline"],
        default="online",
        help="online paths through Ollama, offline loads the local adapter.",
    )
    parser.add_argument(
        "--model",
        default="mistral",
        help="Name of the Ollama model to use when mode=online.",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:11434",
        help="Base URL for the Ollama API when using remote inference.",
    )
    parser.add_argument(
        "--adapter-path",
        type=Path,
        default=Path("wazuh-specialized"),
        help="Path to the LoRA adapter for offline mode.",
    )
    parser.add_argument(
        "--offline-base-model",
        default="Qwen/Qwen2.5-3B",
        help="Hugging Face base model to pair with the LoRA adapter.",
    )
    parser.add_argument(
        "--offline-max-new-tokens",
        type=int,
        default=512,
        help="Generation budget when running offline.",
    )
    parser.add_argument(
        "--offline-temperature",
        type=float,
        default=0.2,
        help="Sampling temperature for the offline model.",
    )
    parser.add_argument(
        "--rule-output",
        type=Path,
        nargs="?",
        const=Path("generated_rules.xml"),
        default=Path("generated_rules.xml"),
        help="Path under the project root where the generated `rule_xml` will be appended (defaults to generated_rules.xml).",
    )

    args = parser.parse_args()
    if args.mode == "offline":
        client = LocalLlmClient(
            adapter_path=args.adapter_path,
            base_model=args.offline_base_model,
            max_response_tokens=args.offline_max_new_tokens,
            temperature=args.offline_temperature,
        )
    else:
        client = OllamaLlmClient(model=args.model, base_url=args.base_url)
    optimizer = WazuhRuleOptimizer(client)
    result = optimizer.optimize_from_files(args.detection_goal, args.rules, args.logs)
    print(json.dumps(result, indent=2))
    if args.rule_output and result.get("rule_xml"):
        existing = ""
        if args.rule_output.exists():
            existing = args.rule_output.read_text(encoding="utf-8")
            if existing and not existing.endswith("\n"):
                existing = existing + "\n"
        args.rule_output.write_text(
            f"{existing}{result['rule_xml']}\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
