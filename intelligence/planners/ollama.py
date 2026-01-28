import json
from typing import Any, Dict

import requests

from intelligence.core.base import Planner
from intelligence.core.utils import extract_json
from intelligence.planners.local_model import _build_planner_prompt


class OllamaPlanner(Planner):
    def __init__(self, base_url: str, model: str, timeout: float):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def plan(self, alert: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
        prompt = _build_planner_prompt(alert, assessment)
        resp = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You are a SOC response planner."},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        content = data["message"]["content"].strip()
        parsed = extract_json(content)
        if not parsed:
            raise ValueError("Ollama planner returned invalid JSON.")
        return parsed
