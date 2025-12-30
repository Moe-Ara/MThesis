"""Ollama client used by agents to generate XML rule outputs."""

import json
from typing import Any, Dict

import requests

from thesis.llm.base import LlmClient


class OllamaLlmClient(LlmClient):
    """Simple wrapper around Ollama's local chat API."""

    def __init__(self, model: str = "mistral", base_url: str = "http://localhost:11434") -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")

    def generate(
        self,
        system_prompt: str,
        user_payload: Dict[str, Any],
        timeout: float = 120.0,
    ) -> Dict[str, Any]:
        """Send the prompt/payload and return the parsed JSON response."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload)},
        ]

        resp = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": False,
            },
            timeout=timeout,
        )
        resp.raise_for_status()

        if not resp.text.strip():
            raise ValueError("Received empty response from Ollama.")

        try:
            data = resp.json()
        except json.JSONDecodeError:
            raise ValueError(f"Ollama returned non-JSON payload: {resp.text!r}") from None

        content = data["message"]["content"].strip()
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {"message": content}
