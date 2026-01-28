import uuid
from typing import Any, Dict, List

from intelligence.core.base import Planner
from intelligence.core.utils import get_path, now_iso


class RulePlanner(Planner):
    def plan(self, alert: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
        return _plan_from_rules(alert, assessment)


def _plan_from_rules(alert: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
    severity = int(assessment.get("severity") or 0)
    confidence = float(assessment.get("confidence") or 0.0)
    criticality = int(get_path(alert, "context.assetCriticality") or 0)
    privileged = bool(get_path(alert, "context.privileged") or False)

    src_ip = get_path(alert, "entities.srcIp")
    username = get_path(alert, "entities.username")
    host_id = get_path(alert, "entities.hostId") or get_path(alert, "entities.hostname")

    if confidence < 0.3:
        strategy = "ObserveMore"
    elif (criticality >= 4 or privileged) and confidence < 0.85:
        strategy = "EscalateToHuman"
    elif confidence >= 0.85 and severity >= 70:
        strategy = "ContainAndCollect"
    elif confidence >= 0.6 and severity >= 50:
        strategy = "Contain"
    else:
        strategy = "NotifyOnly"

    actions: List[Dict[str, Any]] = []
    if strategy == "ObserveMore":
        actions.append(_action("OpenTicket", "Create a tracking ticket.", {}))
    elif strategy == "NotifyOnly":
        actions.append(_action("Notify", "Notify analysts.", {}))
        actions.append(_action("OpenTicket", "Create a tracking ticket.", {}))
    elif strategy in ("Contain", "ContainAndCollect"):
        if src_ip:
            actions.append(_action("BlockIp", "Block suspicious source IP.", {"src_ip": src_ip}))
        if username:
            actions.append(_action("DisableUser", "Disable user account.", {"username": username}))
        if host_id:
            actions.append(_action("IsolateHost", "Isolate host.", {"host_id": host_id}))
        if strategy == "ContainAndCollect":
            actions.append(_action("CollectForensics", "Collect forensic artifacts.", {}))
        actions.append(_action("OpenTicket", "Create a tracking ticket.", {}))
    else:
        actions.append(_action("Notify", "Escalate to human analyst.", {}))
        actions.append(_action("OpenTicket", "Create a tracking ticket.", {}))

    rollback_actions = _build_rollbacks(actions)
    priority = _compute_priority(severity, confidence, criticality)
    summary = f"Strategy={strategy}, Severity={severity}, Confidence={confidence:.2f}"
    rationale = [
        f"Selected strategy {strategy} based on confidence {confidence:.2f} and severity {severity}.",
        f"Asset criticality: {criticality}; privileged identity: {privileged}."
    ]

    return {
        "planId": uuid.uuid4().hex,
        "strategy": strategy,
        "priority": priority,
        "summary": summary,
        "actions": actions,
        "rollbackActions": rollback_actions,
        "rationale": rationale,
        "tags": {
            "environment": get_path(alert, "context.environment") or "unknown",
            "generatedAt": now_iso()
        }
    }


def _compute_priority(severity: int, confidence: float, criticality: int) -> int:
    base = severity + (criticality * 10)
    boosted = base + int(confidence * 20)
    return min(max(boosted, 0), 100)


def _action(action_type: str, rationale: str, parameters: Dict[str, str]) -> Dict[str, Any]:
    defaults = {
        "BlockIp": (55, 30, True),
        "UnblockIp": (10, 5, False),
        "IsolateHost": (70, 60, True),
        "UnisolateHost": (15, 10, False),
        "DisableUser": (65, 50, True),
        "EnableUser": (15, 10, False),
        "KillProcess": (85, 85, False),
        "QuarantineFile": (85, 85, False),
        "OpenTicket": (5, 5, False),
        "Notify": (5, 5, False),
        "CollectForensics": (35, 20, False),
    }
    risk, impact, reversible = defaults.get(action_type, (50, 50, False))
    return {
        "type": action_type,
        "risk": risk,
        "expectedImpact": impact,
        "reversible": reversible,
        "parameters": parameters,
        "rationale": rationale,
    }


def _build_rollbacks(actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rollback_map = {
        "BlockIp": "UnblockIp",
        "IsolateHost": "UnisolateHost",
        "DisableUser": "EnableUser",
    }
    rollbacks = []
    for action in reversed(actions):
        action_type = action.get("type")
        rollback_type = rollback_map.get(action_type)
        if rollback_type:
            rollbacks.append(_action(rollback_type, f"Rollback for {action_type}", action.get("parameters", {})))
    return rollbacks
