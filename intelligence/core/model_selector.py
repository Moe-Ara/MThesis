from typing import List, Optional, Protocol

from intelligence.core.base import Planner, Scorer


class ModelSelector(Protocol):
    def get_scorer(self, requested: Optional[str]) -> Scorer:
        ...

    def get_planner(self, requested: Optional[str]) -> Planner:
        ...

    def list_profiles(self) -> List[str]:
        ...

    def resolve_profile(self, requested: Optional[str]) -> Optional[str]:
        ...
