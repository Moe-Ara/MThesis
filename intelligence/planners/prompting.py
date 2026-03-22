import json
from typing import Any, Dict, Optional


def _normalize_entities(entities: Any) -> Dict[str, Any]:
    if not isinstance(entities, dict):
        return {}
    return {k: v for k, v in entities.items() if v is not None and v != ""}


def _compact_context(context: Any) -> Dict[str, Any]:
    if not isinstance(context, dict):
        return {}
    keys = ["assetCriticality", "privileged", "exposure", "timeSensitivity", "environment"]
    return {k: context.get(k) for k in keys if context.get(k) is not None}


def _compact_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    summary = {
        "sourceSiem": alert.get("sourceSiem"),
        "alertId": alert.get("alertId"),
        "type": alert.get("type"),
        "ruleName": alert.get("ruleName"),
        "severity": alert.get("severity"),
        "entities": _normalize_entities(alert.get("entities")),
        "context": _compact_context(alert.get("context")),
    }
    raw = alert.get("rawPayload")
    if isinstance(raw, dict):
        keep_keys = [
            "technique_id",
            "technique_name",
            "tactic",
            "src_ip",
            "dst_ip",
            "dst_port",
            "process_name",
            "process",
            "username",
            "user",
            "file_hash",
            "event_id",
        ]
        raw_trim = {k: raw.get(k) for k in keep_keys if raw.get(k) is not None}
        if raw_trim:
            summary["rawPayload"] = raw_trim
    return summary


def _compact_assessment(assessment: Dict[str, Any], max_evidence: int = 3) -> Dict[str, Any]:
    if not isinstance(assessment, dict):
        return {}
    evidence = assessment.get("evidence") or []
    if not isinstance(evidence, list):
        evidence = []
    trimmed = [e for e in evidence if e][:max_evidence]
    summary = {
        "severity": assessment.get("severity"),
        "confidence": assessment.get("confidence"),
        "hypothesis": assessment.get("hypothesis"),
    }
    if trimmed:
        summary["evidence"] = trimmed
    return {k: v for k, v in summary.items() if v is not None}


def _decision_features(alert: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
    entities = _normalize_entities(alert.get("entities"))
    context = _compact_context(alert.get("context"))
    features = {
        "severity": assessment.get("severity", alert.get("severity")),
        "confidence": assessment.get("confidence"),
        "assetCriticality": context.get("assetCriticality"),
        "privileged": context.get("privileged"),
        "exposure": context.get("exposure"),
        "timeSensitivity": context.get("timeSensitivity"),
        "has_src_ip": bool(entities.get("srcIp") or entities.get("src_ip")),
        "has_host": bool(entities.get("hostId") or entities.get("host_id") or entities.get("hostname")),
        "has_user": bool(entities.get("username") or entities.get("userName") or entities.get("user")),
        "has_process": bool(entities.get("processName") or entities.get("process_name")),
        "has_file_hash": bool(entities.get("fileHash") or entities.get("file_hash")),
    }
    return {k: v for k, v in features.items() if v is not None}


def build_planner_prompt(alert: Dict[str, Any], assessment: Dict[str, Any]) -> str:
    action_catalog = (
        "Action types (exact parameter keys):\n"
        "- BlockIp: {\"src_ip\": \"<ip>\"}\n"
        "- UnblockIp: {\"src_ip\": \"<ip>\"}\n"
        "- IsolateHost: {\"host_id\": \"<id>\"} (optional \"hostname\")\n"
        "- UnisolateHost: {\"host_id\": \"<id>\"} (optional \"hostname\")\n"
        "- DisableUser: {\"username\": \"<name>\"} (optional \"user_id\")\n"
        "- EnableUser: {\"username\": \"<name>\"} (optional \"user_id\")\n"
        "- KillProcess: {\"host_id\": \"<id>\", \"process_name\": \"<name>\"}\n"
        "- QuarantineFile: {\"host_id\": \"<id>\", \"file_hash\": \"<hash>\"}\n"
        "- OpenTicket: {}\n"
        "- Notify: {}\n"
        "- CollectForensics: {}\n"
    )

    entities = _normalize_entities(alert.get("entities"))
    available = entities.copy()

    confidence = assessment.get("confidence", 0)
    confidence_rule = ""
    if isinstance(confidence, (int, float)) and confidence < 0.60:
        confidence_rule = (
            "LOW CONFIDENCE: only OpenTicket and Notify actions are allowed.\n"
        )

    return (
        "You are a SOC response planner. Return ONLY a valid JSON object.\n"
        "Required keys: planId, strategy, priority, summary, actions, rollbackActions, rationale, tags.\n"
        "Include a reasoning object with keys: summary, evidence (list), constraints (list), action_justifications (object).\n"
        "Each action must include: type, risk, expectedImpact, reversible, parameters, rationale.\n"
        "Rules:\n"
        "- Use only available entity values; never invent values.\n"
        "- Use the exact parameter key names listed below.\n"
        "- Include OpenTicket or Notify in every plan.\n"
        "- Keep actions 1-4 maximum.\n"
        f"{confidence_rule}"
        f"{action_catalog}\n"
        f"Available entities: {json.dumps(available) if available else 'NONE'}\n\n"
        f"Alert:\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n\n"
        f"Assessment:\n{json.dumps(assessment, ensure_ascii=False, indent=2)}\n"
    )


def build_planner_prompt_compact(
    alert: Dict[str, Any], assessment: Dict[str, Any], include_raw: bool = False
) -> str:
    action_catalog = (
        "Action types (exact parameter keys):\n"
        "- BlockIp: {\"src_ip\": \"<ip>\"}\n"
        "- UnblockIp: {\"src_ip\": \"<ip>\"}\n"
        "- IsolateHost: {\"host_id\": \"<id>\"} (optional \"hostname\")\n"
        "- UnisolateHost: {\"host_id\": \"<id>\"} (optional \"hostname\")\n"
        "- DisableUser: {\"username\": \"<name>\"} (optional \"user_id\")\n"
        "- EnableUser: {\"username\": \"<name>\"} (optional \"user_id\")\n"
        "- KillProcess: {\"host_id\": \"<id>\", \"process_name\": \"<name>\"}\n"
        "- QuarantineFile: {\"host_id\": \"<id>\", \"file_hash\": \"<hash>\"}\n"
        "- OpenTicket: {}\n"
        "- Notify: {}\n"
        "- CollectForensics: {}\n"
    )
    entities = _normalize_entities(alert.get("entities"))
    available = entities.copy()

    confidence = assessment.get("confidence", 0)
    confidence_rule = ""
    if isinstance(confidence, (int, float)) and confidence < 0.60:
        confidence_rule = "LOW CONFIDENCE: only OpenTicket and Notify actions are allowed.\n"

    alert_summary = _compact_alert(alert)
    if not include_raw and "rawPayload" in alert_summary:
        alert_summary.pop("rawPayload", None)

    features = _decision_features(alert, assessment)

    return (
        "You are a SOC response planner. Return ONLY a valid JSON object.\n"
        "Required keys: planId, strategy, priority, summary, actions, rollbackActions, rationale, tags.\n"
        "Include a reasoning object with keys: summary, evidence (list), constraints (list), action_justifications (object).\n"
        "Each action must include: type, risk, expectedImpact, reversible, parameters, rationale.\n"
        "Rules:\n"
        "- Use only available entity values; never invent values.\n"
        "- Use the exact parameter key names listed below.\n"
        "- Include OpenTicket or Notify in every plan.\n"
        "- Keep actions 1-4 maximum.\n"
        f"{confidence_rule}"
        f"{action_catalog}\n"
        f"DecisionFeatures: {json.dumps(features, ensure_ascii=False)}\n"
        f"Available entities: {json.dumps(available) if available else 'NONE'}\n\n"
        f"Alert:\n{json.dumps(alert_summary, ensure_ascii=False, indent=2)}\n\n"
        f"Assessment:\n{json.dumps(assessment, ensure_ascii=False, indent=2)}\n"
    )


def build_planner_prompt_minimal(alert: Dict[str, Any], assessment: Dict[str, Any]) -> str:
    action_schema = (
        "Action schema (parameters must match exactly, no extra keys):\n"
        "- BlockIp: {\"src_ip\": \"<ip>\"}\n"
        "- UnblockIp: {\"src_ip\": \"<ip>\"}\n"
        "- IsolateHost: {\"host_id\": \"<id>\", \"hostname\"?: \"<name>\"}\n"
        "- UnisolateHost: {\"host_id\": \"<id>\", \"hostname\"?: \"<name>\"}\n"
        "- DisableUser: {\"username\": \"<name>\", \"user_id\"?: \"<id>\"}\n"
        "- EnableUser: {\"username\": \"<name>\", \"user_id\"?: \"<id>\"}\n"
        "- KillProcess: {\"host_id\": \"<id>\", \"process_name\": \"<name>\"}\n"
        "- QuarantineFile: {\"host_id\": \"<id>\", \"file_hash\": \"<hash>\"}\n"
        "- OpenTicket: {}\n"
        "- Notify: {}\n"
        "- CollectForensics: {}\n"
    )
    entities = _normalize_entities(alert.get("entities"))
    available = entities.copy()

    confidence = assessment.get("confidence", 0)
    confidence_rule = ""
    if isinstance(confidence, (int, float)) and confidence < 0.60:
        confidence_rule = "LOW CONFIDENCE: only OpenTicket and Notify actions are allowed.\n"

    alert_summary = _compact_alert(alert)
    alert_summary.pop("rawPayload", None)
    assessment_summary = _compact_assessment(assessment, max_evidence=3)
    features = _decision_features(alert, assessment)

    return (
        "You are a SOC response planner. Return ONLY a valid JSON object.\n"
        "Required keys: planId, strategy, priority, summary, actions, rollbackActions, rationale, tags.\n"
        "Include a reasoning object with keys: summary, evidence (list), constraints (list), action_justifications (object).\n"
        "Each action must include: type, risk, expectedImpact, reversible, parameters, rationale.\n"
        "Rules:\n"
        "- Use only available entity values; never invent values.\n"
        "- Use the exact parameter key names listed below.\n"
        "- For OpenTicket/Notify/CollectForensics, parameters MUST be {}.\n"
        "- Do not add extra keys anywhere.\n"
        "- Include OpenTicket or Notify in every plan.\n"
        "- Keep actions 1-4 maximum.\n"
        f"{confidence_rule}"
        f"{action_schema}\n"
        f"DecisionFeatures: {json.dumps(features, ensure_ascii=False)}\n"
        f"Available entities: {json.dumps(available) if available else 'NONE'}\n\n"
        f"AlertSummary:\n{json.dumps(alert_summary, ensure_ascii=False, indent=2)}\n\n"
        f"AssessmentSummary:\n{json.dumps(assessment_summary, ensure_ascii=False, indent=2)}\n"
    )


# def build_planner_prompt_minimal(alert, assessment):
#     """Original minimal prompt — too long for T5's 512 token limit (~800 tokens).
#     Replaced by build_planner_prompt_seq2seq for seq2seq models."""
#     pass


def build_planner_prompt_seq2seq(alert: Dict[str, Any], assessment: Dict[str, Any]) -> str:
    """Ultra-compact prompt for seq2seq models that fits within 512 tokens.

    Strips all boilerplate instructions (the model learns these during training)
    and keeps only the variable alert/assessment data.
    """
    entities = _normalize_entities(alert.get("entities"))
    confidence = assessment.get("confidence", 0)
    conf_tag = "LOW" if isinstance(confidence, (int, float)) and confidence < 0.60 else "OK"

    alert_type = alert.get("alertType") or alert.get("type") or alert.get("ruleName") or ""
    severity = assessment.get("severity", alert.get("severity", 0))
    hypothesis = (assessment.get("hypothesis") or "")[:120]
    evidence = assessment.get("evidence") or []
    if isinstance(evidence, list):
        evidence = evidence[:2]
    else:
        evidence = []

    entities_str = json.dumps(entities, ensure_ascii=False) if entities else "{}"

    return (
        f"Plan response for SOC alert.\n"
        f"Type: {alert_type}\n"
        f"Severity: {severity} Confidence: {confidence} ({conf_tag})\n"
        f"Hypothesis: {hypothesis}\n"
        f"Evidence: {json.dumps(evidence, ensure_ascii=False)}\n"
        f"Entities: {entities_str}\n"
    )
