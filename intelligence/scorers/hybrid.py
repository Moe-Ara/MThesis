from typing import Any, Dict, Optional

from intelligence.core.base import Scorer


class HybridScorer(Scorer):
    def __init__(self, local_scorer: Optional[Scorer], ollama_scorer: Optional[Scorer], fallback: Scorer):
        self.local_scorer = local_scorer
        self.ollama_scorer = ollama_scorer
        self.fallback = fallback

    def score(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self.local_scorer:
            result = self.local_scorer.score(alert)
            if result:
                return result
        if self.ollama_scorer:
            result = self.ollama_scorer.score(alert)
            if result:
                return result
        return self.fallback.score(alert)
