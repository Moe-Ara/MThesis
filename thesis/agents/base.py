"""Shared agent abstractions used across the Thesis project."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class Agent(ABC):
    """Minimal interface that every agent in the project should implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the agent."""

    @abstractmethod
    def run(self, **kwargs: Any) -> Dict[str, Any]:
        """Execute the agent’s logic with keyword arguments."""
