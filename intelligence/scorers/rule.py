from typing import Any, Dict, List, Optional, Tuple

from intelligence.core.base import Scorer
from intelligence.core.utils import get_path


def _lower_text(*values: Optional[str]) -> str:
    return " ".join(v or "" for v in values).lower()


def _score_rules(alert: Dict[str, Any]) -> Tuple[int, float, str, List[str]]:
    description = get_path(alert, "ruleName")
    alert_type = get_path(alert, "type")
    text = _lower_text(description, alert_type)

    if any(key in text for key in ("ransomware", "trojan", "malware")):
        return 85, 0.85, "Likely malware activity.", ["keyword:malware"]
    if any(key in text for key in ("brute force", "bruteforce", "failed login")):
        return 60, 0.7, "Possible brute-force attempts.", ["keyword:bruteforce"]
    if "port scan" in text or "scan" in text:
        return 55, 0.65, "Possible scanning activity.", ["keyword:scan"]
    if "benign" in text:
        return 20, 0.2, "Likely benign noise.", ["keyword:benign"]

    base = get_path(alert, "severity")
    if isinstance(base, int):
        return min(max(base, 0), 100), 0.5, "Severity-based assessment.", ["source:severity"]

    return 40, 0.5, "Heuristic assessment.", ["source:default"]


class RuleScorer(Scorer):
    def score(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        severity, confidence, hypothesis, evidence = _score_rules(alert)
        return {
            "severity": severity,
            "confidence": confidence,
            "hypothesis": hypothesis,
            "evidence": evidence,
        }
