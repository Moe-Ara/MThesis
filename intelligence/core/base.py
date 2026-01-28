from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class Scorer(ABC):
    @abstractmethod
    def score(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


class Planner(ABC):
    @abstractmethod
    def plan(self, alert: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError
