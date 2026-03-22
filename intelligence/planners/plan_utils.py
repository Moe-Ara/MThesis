import uuid
from typing import Any, Dict, List, Optional


_STRATEGY_MAP = {
    "observemore": "ObserveMore",
    "notifyonly": "NotifyOnly",
    "contain": "Contain",
    "containandcollect": "ContainAndCollect",
    "escalatetohuman": "EscalateToHuman",
}

_REQUIRED_PARAMS = {
    "BlockIp": ["src_ip"],
    "UnblockIp": ["src_ip"],
    "IsolateHost": ["host_id"],
    "UnisolateHost": ["host_id"],
    "DisableUser": ["username"],
    "EnableUser": ["username"],
    "KillProcess": ["host_id", "process_name"],
    "QuarantineFile": ["host_id", "file_hash"],
}

_ALLOWED_ACTIONS = {
    "BlockIp",
    "UnblockIp",
    "IsolateHost",
    "UnisolateHost",
    "DisableUser",
    "EnableUser",
    "KillProcess",
    "QuarantineFile",
    "OpenTicket",
    "Notify",
    "CollectForensics",
}

_ALLOWED_PARAMS = {
    "BlockIp": {"src_ip"},
    "UnblockIp": {"src_ip"},
    "IsolateHost": {"host_id", "hostname"},
    "UnisolateHost": {"host_id", "hostname"},
    "DisableUser": {"username", "user_id"},
    "EnableUser": {"username", "user_id"},
    "KillProcess": {"host_id", "process_name"},
    "QuarantineFile": {"host_id", "file_hash"},
    "OpenTicket": set(),
    "Notify": set(),
    "CollectForensics": set(),
}

_PARAM_ALIASES = {
    "hostId": "host_id",
    "hostID": "host_id",
    "fileHash": "file_hash",
    "filehash": "file_hash",
    "srcIp": "src_ip",
    "srcIP": "src_ip",
    "processName": "process_name",
    "process": "process_name",
    "userName": "username",
    "user": "username",
}

_SAFE_ACTIONS = {"OpenTicket", "Notify"}
_CONTAIN_ACTIONS = {"BlockIp", "IsolateHost", "DisableUser", "KillProcess", "QuarantineFile"}

_ACTION_REASON = {
    "BlockIp": "Block the source IP to stop continued malicious traffic.",
    "UnblockIp": "Rollback containment once the threat is verified resolved.",
    "IsolateHost": "Isolate the host to prevent lateral movement during investigation.",
    "UnisolateHost": "Restore host connectivity after containment is lifted.",
    "DisableUser": "Disable the user account to prevent credential abuse.",
    "EnableUser": "Re-enable the user account after remediation.",
    "KillProcess": "Terminate the suspicious process to halt malicious activity.",
    "QuarantineFile": "Quarantine the file to prevent execution while preserving evidence.",
    "OpenTicket": "Create an auditable record for analyst review.",
    "Notify": "Notify the SOC team to coordinate investigation.",
    "CollectForensics": "Collect forensics to preserve evidence and confirm scope.",
}

_ENTITY_KEYS = {
    "src_ip": ["srcIp", "src_ip", "sourceIp"],
    "host_id": ["hostId", "host_id", "hostname"],
    "username": ["username", "userName", "user"],
    "process_name": ["processName", "process_name"],
    "file_hash": ["fileHash", "file_hash"],
}


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return default


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


def _normalize_strategy(value: Any) -> str:
    if not value:
        return "NotifyOnly"
    raw = str(value).strip().lower()
    key = "".join(ch for ch in raw if ch.isalnum())
    return _STRATEGY_MAP.get(key, "NotifyOnly")


def _entity_value(entities: Dict[str, Any], key: str) -> Optional[Any]:
    for candidate in _ENTITY_KEYS.get(key, []):
        value = entities.get(candidate)
        if value:
            return value
    return None


def _sanitize_actions(actions: List[Dict[str, Any]], alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    entities = alert.get("entities") or {}
    if not isinstance(entities, dict):
        entities = {}

    cleaned: List[Dict[str, Any]] = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        action_type = str(action.get("type") or "").strip()
        if not action_type or action_type not in _ALLOWED_ACTIONS:
            continue

        params = action.get("parameters")
        if not isinstance(params, dict):
            params = {}

        allowed_params = _ALLOWED_PARAMS.get(action_type, set())
        if not allowed_params:
            params = {}
        else:
            cleaned_params: Dict[str, Any] = {}
            for key, value in params.items():
                if key in allowed_params:
                    cleaned_params[key] = value
                    continue
                alias = _PARAM_ALIASES.get(key)
                if alias and alias in allowed_params and alias not in cleaned_params:
                    cleaned_params[alias] = value
            params = cleaned_params

        required = _REQUIRED_PARAMS.get(action_type, [])
        missing = False
        for param_key in required:
            if not params.get(param_key):
                value = _entity_value(entities, param_key)
                if value:
                    params[param_key] = value
                else:
                    missing = True
                    break
        if missing:
            continue

        cleaned.append(
            {
                "type": action_type,
                "risk": max(0, min(100, _to_int(action.get("risk", 0)))),
                "expectedImpact": max(0, min(100, _to_int(action.get("expectedImpact", 0)))),
                "reversible": _to_bool(action.get("reversible", False)),
                "parameters": params,
                "rationale": str(action.get("rationale") or "").strip(),
            }
        )

    return cleaned


def _open_ticket_action() -> Dict[str, Any]:
    return {
        "type": "OpenTicket",
        "risk": 5,
        "expectedImpact": 5,
        "reversible": False,
        "parameters": {},
        "rationale": "Document the incident for analyst review.",
    }


def _is_low_confidence(assessment: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(assessment, dict):
        return False
    confidence = assessment.get("confidence")
    return isinstance(confidence, (int, float)) and confidence < 0.6


def _build_reasoning(
    alert: Dict[str, Any],
    assessment: Optional[Dict[str, Any]],
    actions: List[Dict[str, Any]],
    strategy: str,
    derived: bool = True,
) -> Dict[str, Any]:
    evidence = []
    if isinstance(assessment, dict):
        ev = assessment.get("evidence")
        if isinstance(ev, list):
            evidence.extend([str(e) for e in ev if e])
        hypothesis = assessment.get("hypothesis")
    else:
        hypothesis = None

    if not evidence:
        entities = alert.get("entities") or {}
        if isinstance(entities, dict):
            for key in ("srcIp", "hostId", "username", "fileHash", "processName"):
                val = entities.get(key)
                if val:
                    evidence.append(f"{key}={val}")

    constraints = [
        "Actions limited to available entity values.",
        "Max 4 actions enforced.",
        "OpenTicket or Notify always included.",
    ]
    if _is_low_confidence(assessment):
        constraints.append("Low confidence: only safe actions allowed.")

    action_justifications = {}
    for action in actions:
        action_type = action.get("type")
        if not action_type:
            continue
        rationale = str(action.get("rationale") or "").strip()
        if not rationale:
            rationale = _ACTION_REASON.get(action_type, "Action selected by policy.")
        action_justifications[action_type] = rationale

    summary = hypothesis or f"Strategy selected: {strategy}."

    return {
        "source": "derived" if derived else "model",
        "summary": summary,
        "evidence": evidence[:6],
        "constraints": constraints,
        "action_justifications": action_justifications,
    }


def derive_strategy(
    alert: Dict[str, Any], assessment: Optional[Dict[str, Any]], plan: Dict[str, Any]
) -> str:
    confidence = None
    severity = alert.get("severity", 0)
    if isinstance(assessment, dict):
        confidence = assessment.get("confidence")
        severity = assessment.get("severity", severity)

    try:
        conf_val = float(confidence) if confidence is not None else 0.0
    except (TypeError, ValueError):
        conf_val = 0.0

    actions = plan.get("actions") or []
    action_types = {
        a.get("type") for a in actions if isinstance(a, dict) and isinstance(a.get("type"), str)
    }

    if conf_val < 0.3:
        return "ObserveMore"

    if not action_types or action_types.issubset({"OpenTicket", "Notify", "CollectForensics"}):
        return "NotifyOnly"

    if "CollectForensics" in action_types:
        return "ContainAndCollect"

    if action_types & _CONTAIN_ACTIONS:
        return "Contain"

    if conf_val >= 0.85 and isinstance(severity, (int, float)) and severity >= 70:
        return "ContainAndCollect"
    if conf_val >= 0.6 and isinstance(severity, (int, float)) and severity >= 50:
        return "Contain"
    return "NotifyOnly"


def sanitize_plan(
    plan: Dict[str, Any],
    alert: Dict[str, Any],
    assessment: Optional[Dict[str, Any]] = None,
    derive_strategy_from_actions: bool = False,
) -> Dict[str, Any]:
    if "plan" in plan and isinstance(plan["plan"], dict):
        plan = plan["plan"]

    plan_id = str(plan.get("planId") or uuid.uuid4().hex)
    strategy = _normalize_strategy(plan.get("strategy"))
    priority = max(0, min(100, _to_int(plan.get("priority", 50), 50)))
    summary = str(plan.get("summary") or "Auto-generated response plan.").strip()

    actions_raw = plan.get("actions")
    if not isinstance(actions_raw, list):
        actions_raw = []
    actions = _sanitize_actions(actions_raw, alert)
    if _is_low_confidence(assessment):
        actions = [action for action in actions if action.get("type") in _SAFE_ACTIONS]
        if strategy not in ("ObserveMore", "NotifyOnly"):
            strategy = "NotifyOnly"

    if not actions:
        actions = [_open_ticket_action()]

    if not any(action.get("type") in _SAFE_ACTIONS for action in actions):
        actions.append(_open_ticket_action())

    if len(actions) > 4:
        actions = actions[:4]
        if not any(action.get("type") in _SAFE_ACTIONS for action in actions):
            actions[-1] = _open_ticket_action()

    rollback_actions = plan.get("rollbackActions")
    if not isinstance(rollback_actions, list):
        rollback_actions = []

    rationale = plan.get("rationale")
    if isinstance(rationale, list):
        rationale_list = [str(item).strip() for item in rationale if str(item).strip()]
    elif isinstance(rationale, str):
        rationale_list = [rationale.strip()] if rationale.strip() else []
    else:
        rationale_list = []

    tags = plan.get("tags")
    if not isinstance(tags, dict):
        tags = {}

    reasoning = plan.get("reasoning")
    if isinstance(reasoning, dict):
        reasoning_payload = reasoning
        if "source" not in reasoning_payload:
            reasoning_payload["source"] = "model"
    else:
        reasoning_payload = _build_reasoning(
            alert, assessment, actions, strategy, derived=True
        )

    if derive_strategy_from_actions:
        strategy = derive_strategy(alert, assessment, {"actions": actions, "strategy": strategy})

    return {
        "planId": plan_id,
        "strategy": strategy,
        "priority": priority,
        "summary": summary,
        "actions": actions,
        "rollbackActions": rollback_actions,
        "rationale": rationale_list,
        "reasoning": reasoning_payload,
        "tags": tags,
    }
