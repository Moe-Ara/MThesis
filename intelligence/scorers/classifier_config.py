from typing import Dict

SEVERITY_CLASSES = ["benign", "low", "medium", "high", "critical"]
SEVERITY_THRESHOLDS = [20, 45, 65, 85, 100]


def severity_to_class(severity: float) -> str:
    try:
        value = float(severity)
    except (TypeError, ValueError):
        return "medium"

    if value <= SEVERITY_THRESHOLDS[0]:
        return "benign"
    if value <= SEVERITY_THRESHOLDS[1]:
        return "low"
    if value <= SEVERITY_THRESHOLDS[2]:
        return "medium"
    if value <= SEVERITY_THRESHOLDS[3]:
        return "high"
    return "critical"


def default_severity_for_class(label: str) -> int:
    defaults: Dict[str, int] = {
        "benign": 10,
        "low": 30,
        "medium": 55,
        "high": 75,
        "critical": 92,
    }
    return defaults.get(label, 55)
