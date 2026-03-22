from typing import Any, Dict, Optional

from intelligence.core.base import Scorer
from intelligence.scorers.classifier_config import severity_to_class


class CalibratedScorer(Scorer):
    """Fuse a classifier (for severity/confidence) with an explainer (LLM) for narrative."""

    def __init__(
        self,
        classifier: Optional[Scorer],
        explainer: Optional[Scorer],
        confidence_floor: float = 0.15,
        confidence_ceiling: float = 0.99,
    ):
        self.classifier = classifier
        self.explainer = explainer
        self.confidence_floor = confidence_floor
        self.confidence_ceiling = confidence_ceiling

    def score(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        base = self.classifier.score(alert) if self.classifier else None
        narrative = self.explainer.score(alert) if self.explainer else None

        if not base and not narrative:
            return None

        result = dict(narrative) if narrative else dict(base)

        if base:
            hypothesis = result.get("hypothesis") or base.get("hypothesis")
            evidence = result.get("evidence") or base.get("evidence")
            if isinstance(hypothesis, str) and hypothesis.strip():
                result["hypothesis"] = hypothesis.strip()
            if isinstance(evidence, list) and evidence:
                result["evidence"] = [str(item).strip() for item in evidence if str(item).strip()]

        if "severity" in result:
            try:
                severity = int(round(float(result["severity"])))
            except (TypeError, ValueError):
                severity = 0
            result["severity"] = max(0, min(100, severity))

        if "confidence" in result:
            try:
                confidence = float(result["confidence"])
            except (TypeError, ValueError):
                confidence = 0.5
            if base and "severity" in result and "severity" in base:
                if severity_to_class(result["severity"]) == severity_to_class(base["severity"]):
                    try:
                        base_conf = float(base.get("confidence", 0.0))
                    except (TypeError, ValueError):
                        base_conf = 0.0
                    confidence = max(confidence, base_conf)
            confidence = max(self.confidence_floor, min(self.confidence_ceiling, confidence))
            result["confidence"] = confidence

        if "evidence" not in result or not isinstance(result.get("evidence"), list):
            result["evidence"] = []

        if "hypothesis" not in result or not str(result.get("hypothesis") or "").strip():
            result["hypothesis"] = "Automated threat assessment."

        return result
