from typing import Any, Dict, Optional

import requests

from intelligence.core.base import Scorer
from intelligence.core.utils import extract_json, repair_json
from intelligence.scorers.classifier_config import default_severity_for_class
from intelligence.scorers.local_model import _build_scorer_prompt


class OllamaScorer(Scorer):
    def __init__(
        self,
        base_url: str,
        model: str,
        timeout: float,
        temperature: float = 0.1,
        top_p: float = 0.9,
        num_predict: Optional[int] = None,
        repeat_penalty: Optional[float] = None,
        json_mode: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self.top_p = top_p
        self.num_predict = num_predict
        self.repeat_penalty = repeat_penalty
        self.json_mode = json_mode
        self._system_prompt = (
            "You are a SOC threat scoring assistant. "
            "Return ONLY a valid JSON object with keys: severity, confidence, hypothesis, evidence. "
            "Calibrate confidence: >=0.75 only with strong evidence, 0.4-0.74 when ambiguous, <0.4 for likely benign. "
            "Use double quotes for all keys/strings. No markdown, no extra text."
        )

    def score(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        prompt = _build_scorer_prompt(alert)
        try:
            content = self._chat(prompt)
            parsed = extract_json(content) or repair_json(content)
            if not parsed or self._missing_fields(parsed):
                repaired = self._repair_json_with_model(content)
                parsed = extract_json(repaired) or repair_json(repaired)
            if not parsed or self._missing_fields(parsed):
                return None
            return self._normalize_score(parsed)
        except Exception:
            return None

    def _missing_fields(self, payload: Dict[str, Any]) -> bool:
        required = ("severity", "confidence", "hypothesis", "evidence")
        return any(key not in payload for key in required)

    def _normalize_score(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        severity_raw = payload.get("severity", 0)
        severity = 0
        if isinstance(severity_raw, str):
            sev_text = severity_raw.strip().lower()
            if sev_text in ("benign", "low", "medium", "high", "critical"):
                severity = default_severity_for_class(sev_text)
            else:
                try:
                    severity = int(round(float(severity_raw)))
                except (TypeError, ValueError):
                    severity = 0
        else:
            try:
                severity = int(round(float(severity_raw)))
            except (TypeError, ValueError):
                severity = 0

        confidence_raw = payload.get("confidence", 0.5)
        try:
            confidence = float(confidence_raw)
        except (TypeError, ValueError):
            confidence = 0.5

        if confidence > 1.0 and confidence <= 100.0:
            confidence = confidence / 100.0
        severity = max(0, min(100, severity))
        confidence = max(0.0, min(1.0, confidence))

        hypothesis = str(payload.get("hypothesis") or "").strip()
        evidence_raw = payload.get("evidence")
        if isinstance(evidence_raw, list):
            evidence = [str(item).strip() for item in evidence_raw if str(item).strip()]
        else:
            evidence = []

        if not hypothesis:
            hypothesis = "Automated threat assessment."

        return {
            "severity": severity,
            "confidence": confidence,
            "hypothesis": hypothesis,
            "evidence": evidence,
        }

    def _chat(self, prompt: str) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self._system_prompt},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }
        options = self._build_options()
        if options:
            payload["options"] = options
        if self.json_mode:
            payload["format"] = "json"
        resp = requests.post(
            f"{self.base_url}/api/chat",
            json=payload,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["message"]["content"].strip()

    def _build_options(self) -> Dict[str, Any]:
        options: Dict[str, Any] = {}
        if self.temperature is not None:
            options["temperature"] = self.temperature
        if self.top_p is not None:
            options["top_p"] = self.top_p
        if self.num_predict is not None:
            options["num_predict"] = self.num_predict
        if self.repeat_penalty is not None:
            options["repeat_penalty"] = self.repeat_penalty
        return options

    def _repair_json_with_model(self, text: str) -> str:
        repair_prompt = (
            "Fix the response so it is a single valid JSON object with keys "
            "severity, confidence, hypothesis, evidence. Output ONLY JSON.\n\n"
            f"Response:\n{text}"
        )
        return self._chat(repair_prompt)


def ollama_ok(base_url: str) -> bool:
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False
