"""Base definitions for LLM clients used by agents."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class LlmClient(ABC):
    """Minimal interface that every LLM client must implement."""

    @abstractmethod
    def generate(
        self,
        system_prompt: str,
        user_payload: Dict[str, Any],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Return the parsed JSON response from the model."""
