from typing import Any, Dict, Optional

import requests

from intelligence.core.base import Scorer
from intelligence.core.utils import extract_json
from intelligence.scorers.local_model import _build_scorer_prompt


class OllamaScorer(Scorer):
    def __init__(self, base_url: str, model: str, timeout: float):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def score(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        prompt = _build_scorer_prompt(alert)
        try:
            resp = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a SOC threat scoring assistant."},
                        {"role": "user", "content": prompt},
                    ],
                    "stream": False,
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["message"]["content"].strip()
            return extract_json(content)
        except Exception:
            return None


def ollama_ok(base_url: str) -> bool:
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False
