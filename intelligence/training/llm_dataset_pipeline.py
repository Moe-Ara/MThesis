from __future__ import annotations

import argparse
import csv
import json
import random
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional
from uuid import uuid4

import requests


PLAN_STRATEGIES = [
    "ObserveMore",
    "NotifyOnly",
    "Contain",
    "ContainAndCollect",
    "EscalateToHuman",
]

ACTION_TYPES = [
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
]

ACTION_DEFAULTS = {
    "BlockIp": {"risk": 55, "impact": 30, "reversible": True},
    "UnblockIp": {"risk": 10, "impact": 5, "reversible": False},
    "IsolateHost": {"risk": 70, "impact": 60, "reversible": True},
    "UnisolateHost": {"risk": 15, "impact": 10, "reversible": False},
    "DisableUser": {"risk": 65, "impact": 50, "reversible": True},
    "EnableUser": {"risk": 15, "impact": 10, "reversible": False},
    "KillProcess": {"risk": 85, "impact": 85, "reversible": False},
    "QuarantineFile": {"risk": 85, "impact": 85, "reversible": False},
    "OpenTicket": {"risk": 5, "impact": 5, "reversible": False},
    "Notify": {"risk": 5, "impact": 5, "reversible": False},
    "CollectForensics": {"risk": 35, "impact": 20, "reversible": False},
}

ROLLBACK_MAP = {
    "BlockIp": "UnblockIp",
    "IsolateHost": "UnisolateHost",
    "DisableUser": "EnableUser",
}


def _clamp(value: float, min_value: float, max_value: float) -> float:
    return max(min_value, min(value, max_value))


def _coerce_value(value):
    if isinstance(value, dict):
        for key in ("#text", "value", "Value"):
            if key in value:
                return value[key]
    return value


def _safe_get(record: Dict, keys: Iterable[str]) -> Optional[str]:
    for key in keys:
        value = None
        if "." in key:
            current = record
            for part in key.split("."):
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    current = None
                    break
            value = current
        else:
            value = record.get(key)
        value = _coerce_value(value)
        if value not in (None, ""):
            return str(value)
    return None


def _coerce_int(value: object, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _coerce_float(value: object, default: Optional[float]) -> Optional[float]:
    if value is None:
        return default
    if isinstance(value, bool):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False
    return default


def _normalize_enum(value: object, options: List[str]) -> Optional[str]:
    if value is None:
        return None
    value_str = str(value)
    normalized = value_str.replace("_", "").replace("-", "").lower()
    for option in options:
        if option.replace("_", "").replace("-", "").lower() == normalized:
            return option
    return None


def _severity_from_label(label: str) -> float:
    label = label.lower()
    if "benign" in label or "normal" in label:
        return 0.15
    if any(term in label for term in ["dos", "ddos", "bot", "infiltration"]):
        return 0.75
    if any(term in label for term in ["bruteforce", "brute force", "ssh", "ftp"]):
        return 0.6
    if any(term in label for term in ["web", "sql", "xss"]):
        return 0.55
    if any(term in label for term in ["malware", "ransom", "trojan"]):
        return 0.85
    return 0.45


@dataclass
class AlertRecord:
    source: str
    source_file: str
    record_id: str
    alert: Dict


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout: int):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str, system: str, temperature: float, max_tokens: int) -> str:
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "system": system,
                "stream": False,
                "options": {"temperature": temperature, "num_predict": max_tokens},
                "format": "json",
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        return payload.get("response", "").strip()


def _build_alert_base(
    source: str,
    alert_type: str,
    timestamp: str | None,
    severity: float,
    entities: Dict,
    context: Dict,
    raw: Dict,
) -> Dict:
    return {
        "source": source,
        "type": alert_type,
        "timestamp": timestamp or datetime.utcnow().isoformat(),
        "severity": round(severity * 100, 1),
        "entities": entities,
        "context": context,
        "raw": raw,
    }


def _normalize_entities(base: Dict) -> Dict:
    entities = {k: v for k, v in base.items() if v not in (None, "")}

    if "user" in entities and "username" not in entities:
        entities["username"] = entities["user"]
    if "host" in entities and "hostname" not in entities:
        entities["hostname"] = entities["host"]
    if "process" in entities and "processName" not in entities:
        entities["processName"] = entities["process"]
    if "file_hash" in entities and "fileHash" not in entities:
        entities["fileHash"] = entities["file_hash"]

    return entities

def _parse_cic_record(record: Dict, source_file: str, index: int) -> AlertRecord:
    label = record.get("Label") or record.get("label") or "unknown"
    alert_type = label.replace(" ", "_").replace("-", "_")
    severity = _severity_from_label(label)

    entities = _normalize_entities(
        {
            "src_ip": _safe_get(record, ["Src IP", "src_ip", "Source IP"]),
            "dest_ip": _safe_get(record, ["Dst IP", "dst_ip", "Destination IP"]),
            "src_port": _safe_get(record, ["Src Port", "src_port", "Source Port"]),
            "dest_port": _safe_get(record, ["Dst Port", "dst_port", "Destination Port"]),
            "protocol": _safe_get(record, ["Protocol", "protocol"]),
            "host_id": _safe_get(record, ["Dst IP", "dst_ip", "Destination IP"]),
        }
    )

    metrics_keys = [
        ("Flow Duration", "flow_duration"),
        ("Total Fwd Packets", "tot_fwd_pkts"),
        ("Total Backward Packets", "tot_bwd_pkts"),
        ("Flow Bytes/s", "flow_bytes_s"),
        ("Flow Packets/s", "flow_pkts_s"),
        ("Fwd Packet Length Mean", "fwd_pkt_len_mean"),
        ("Bwd Packet Length Mean", "bwd_pkt_len_mean"),
        ("Packet Length Mean", "pkt_len_mean"),
        ("Packet Length Std", "pkt_len_std"),
        ("SYN Flag Count", "syn_flag_cnt"),
        ("ACK Flag Count", "ack_flag_cnt"),
        ("PSH Flag Count", "psh_flag_cnt"),
        ("RST Flag Count", "rst_flag_cnt"),
    ]

    flow_metrics: Dict[str, float] = {}
    for src_key, dest_key in metrics_keys:
        value = record.get(src_key)
        parsed = _coerce_float(value, default=None)
        if parsed is not None:
            flow_metrics[dest_key] = parsed

    attack_category = label.split("-")[0].strip() if "-" in label else label

    context = {
        "dataset": "CIC-IDS2018",
        "label": label,
        "attack_category": attack_category,
    }
    if flow_metrics:
        context["flow"] = flow_metrics

    timestamp = _safe_get(record, ["Timestamp", "timestamp", "Flow Timestamp"])

    alert = _build_alert_base(
        source="cic_ids2018",
        alert_type=alert_type,
        timestamp=timestamp,
        severity=severity,
        entities=entities,
        context=context,
        raw={"label": label},
    )

    return AlertRecord("cic_ids2018", source_file, f"cic-{index}", alert)


def _extract_event_data(event_data: object) -> Dict:
    if isinstance(event_data, dict):
        return event_data
    if isinstance(event_data, list):
        parsed = {}
        for item in event_data:
            if isinstance(item, dict) and "Name" in item:
                parsed[item.get("Name") or ""] = item.get("#text") or item.get("Value")
        return parsed
    return {}


def _parse_mordor_record(record: Dict, source_file: str, index: int) -> AlertRecord:
    if isinstance(record.get("Event"), dict):
        record = record["Event"]

    system = record.get("System", {}) if isinstance(record.get("System"), dict) else {}
    event_data = _extract_event_data(record.get("EventData"))

    label = _safe_get(
        record,
        ["EventName", "Task", "TaskCategory", "Channel", "EventID", "System.EventID"],
    )
    event_id = _safe_get(record, ["EventID", "System.EventID", "System.EventID.#text"])

    alert_type = (label or f"EventID_{event_id}" or "unknown").replace(" ", "_")
    severity = 0.4
    if label and any(term in label.lower() for term in ["malware", "credential", "ransom", "dump", "exfil"]):
        severity = 0.8
    if event_id in {"4625", "4648", "4768", "4771"}:
        severity = max(severity, 0.6)

    entities = _normalize_entities(
        {
            "user": _safe_get(event_data, ["SubjectUserName", "TargetUserName", "AccountName", "User"]),
            "host": _safe_get(system, ["Computer", "Hostname"]),
            "src_ip": _safe_get(event_data, ["IpAddress", "SourceNetworkAddress", "SourceIp"]),
            "dest_ip": _safe_get(event_data, ["DestinationAddress", "DestAddress", "DestinationIp"]),
            "process": _safe_get(event_data, ["Image", "ProcessName", "Process"]),
            "command_line": _safe_get(event_data, ["CommandLine", "CommandLineText"]),
            "file_hash": _safe_get(event_data, ["Hashes", "Hash", "FileHash"]),
            "pid": _safe_get(event_data, ["ProcessId", "ProcessID", "Pid"]),
            "host_id": _safe_get(system, ["Computer", "Hostname"]),
        }
    )

    context = {
        "dataset": "mordor",
        "event_id": event_id,
    }

    timestamp = _safe_get(record, ["TimeCreated", "System.TimeCreated", "@timestamp", "UtcTime", "time"])

    alert = _build_alert_base(
        source="mordor",
        alert_type=alert_type,
        timestamp=timestamp,
        severity=severity,
        entities=entities,
        context=context,
        raw={"event_id": event_id, "label": label},
    )

    return AlertRecord("mordor", source_file, f"mordor-{index}", alert)


def _parse_darpa_record(record: Dict, source_file: str, index: int) -> AlertRecord:
    event_type = _safe_get(record, ["eventType", "event_type", "type", "activity", "operation"])
    alert_type = (event_type or "darpa_event").replace(" ", "_")

    timestamp = _safe_get(record, ["timestamp", "time", "eventTime", "event_time", "ts"])

    subject = record.get("subject") if isinstance(record.get("subject"), dict) else {}
    obj = record.get("object") if isinstance(record.get("object"), dict) else {}

    entities = _normalize_entities(
        {
            "user": _safe_get(record, ["user", "username", "principal", "subject.user"])
            or _safe_get(subject, ["user", "uid"]),
            "host": _safe_get(record, ["host", "hostname", "machine", "agent"])
            or _safe_get(subject, ["host", "hostname"]),
            "src_ip": _safe_get(record, ["src_ip", "sourceIp", "source.ip", "src"]),
            "dest_ip": _safe_get(record, ["dst_ip", "destIp", "destination.ip", "dst"]),
            "process": _safe_get(record, ["process", "proc", "image", "exe", "command"])
            or _safe_get(subject, ["commandLine", "cmdLine", "exe"]),
            "pid": _safe_get(record, ["pid", "processId", "process_id"]) or _safe_get(subject, ["pid"]),
            "file_path": _safe_get(obj, ["path", "file", "file_path"]),
            "host_id": _safe_get(record, ["host_id", "hostId"]) or _safe_get(subject, ["host_id", "hostId"]),
        }
    )

    severity = 0.45
    if event_type and any(term in event_type.lower() for term in ["exec", "connect", "write", "delete"]):
        severity = 0.6

    context = {
        "dataset": "darpa_tc",
        "event_type": event_type,
    }

    alert = _build_alert_base(
        source="darpa_tc",
        alert_type=alert_type,
        timestamp=timestamp,
        severity=severity,
        entities=entities,
        context=context,
        raw={"event_type": event_type},
    )

    return AlertRecord("darpa_tc", source_file, f"darpa-{index}", alert)


def _load_csv_samples(path: Path, sample: int) -> Iterator[Dict]:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        rows = []
        for row in reader:
            rows.append(row)
            if len(rows) >= sample:
                break
        return iter(rows)


def _load_json_samples(path: Path, sample: int) -> Iterator[Dict]:
    if path.suffix.lower() == ".jsonl":
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            rows = []
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if len(rows) >= sample:
                    break
            return iter(rows)

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        try:
            payload = json.load(handle)
        except json.JSONDecodeError:
            return iter([])
        if isinstance(payload, list):
            return iter(payload[:sample])
        if isinstance(payload, dict):
            if "records" in payload and isinstance(payload["records"], list):
                return iter(payload["records"][:sample])
            return iter([payload])
        return iter([])


def _discover_files(root: Path, patterns: List[str], max_file_mb: int) -> List[Path]:
    files: List[Path] = []
    for pattern in patterns:
        for path in root.rglob(pattern):
            try:
                if path.stat().st_size > max_file_mb * 1024 * 1024:
                    continue
            except FileNotFoundError:
                continue
            files.append(path)
    return files


def load_alerts_from_sources(source_root: Path, max_records: int, max_file_mb: int) -> List[AlertRecord]:
    alerts: List[AlertRecord] = []

    cic_root = source_root / "cic_ids2018"
    if cic_root.exists():
        cic_files = _discover_files(cic_root, ["*.csv"], max_file_mb)
        for file_path in cic_files:
            for idx, row in enumerate(_load_csv_samples(file_path, max_records)):
                alerts.append(_parse_cic_record(row, str(file_path), idx))
                if len(alerts) >= max_records:
                    return alerts

    mordor_root = source_root / "mordor"
    if mordor_root.exists():
        mordor_files = _discover_files(mordor_root, ["*.json", "*.jsonl"], max_file_mb)
        for file_path in mordor_files:
            for idx, row in enumerate(_load_json_samples(file_path, max_records)):
                alerts.append(_parse_mordor_record(row, str(file_path), idx))
                if len(alerts) >= max_records:
                    return alerts

    darpa_root = source_root / "darpa_tc"
    if darpa_root.exists():
        darpa_files = _discover_files(darpa_root, ["*.json", "*.jsonl"], max_file_mb)
        for file_path in darpa_files:
            for idx, row in enumerate(_load_json_samples(file_path, max_records)):
                alerts.append(_parse_darpa_record(row, str(file_path), idx))
                if len(alerts) >= max_records:
                    return alerts

    return alerts

def _build_assessment(alert: Dict) -> Dict:
    confidence = round(min(0.95, 0.4 + (alert.get("severity", 0) / 200)), 2)
    return {
        "confidence": confidence,
        "severity": alert.get("severity", 50),
        "hypothesis": f"Initial hypothesis for {alert.get('type', 'alert')}",
        "evidence": ["dataset: " + str(alert.get("context", {}).get("dataset", "unknown"))],
        "recommendedActions": [],
    }


def _build_scoring_messages(alert: Dict) -> List[Dict[str, str]]:
    system = (
        "You are a SOC scoring model. Output strict JSON with fields: "
        "severity (0-100 int), confidence (0-1 float), hypothesis (string), "
        "evidence (array of strings), recommendedActions (array of ActionType strings). "
        f"Allowed ActionType values: {', '.join(ACTION_TYPES)}."
    )
    user = f"Alert JSON:\n{json.dumps(alert, indent=2)}"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _build_plan_messages(alert: Dict) -> List[Dict[str, str]]:
    assessment = _build_assessment(alert)
    system = (
        "You are a SOC planner. Output strict JSON DecisionPlan with fields: "
        "planId (string), strategy (string), priority (0-100 int), summary (string), "
        "actions (array of PlannedAction), rollbackActions (array of PlannedAction), "
        "rationale (array of strings), tags (object string->string). "
        "PlannedAction schema: {actionId (string), type (ActionType), risk (0-100 int), "
        "expectedImpact (0-100 int), reversible (bool), durationSeconds (int or null), "
        "parameters (object string->string), rationale (string)}. "
        f"Allowed strategy values: {', '.join(PLAN_STRATEGIES)}. "
        f"Allowed ActionType values: {', '.join(ACTION_TYPES)}. "
        "Rules: include 1-4 actions, include rollbacks for reversible actions, "
        "only include durationSeconds for temporary actions like BlockIp or IsolateHost."
    )

    user = (
        "Alert JSON:\n"
        f"{json.dumps(alert, indent=2)}\n\n"
        "Assessment JSON:\n"
        f"{json.dumps(assessment, indent=2)}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _extract_json(text: str) -> Dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start : end + 1])
    return {}


def _default_strategy(severity: float) -> str:
    if severity >= 80:
        return "ContainAndCollect"
    if severity >= 60:
        return "Contain"
    if severity >= 40:
        return "NotifyOnly"
    return "ObserveMore"


def _default_actions(alert: Dict) -> List[str]:
    alert_type = str(alert.get("type", "")).lower()
    if "port_scan" in alert_type or "scan" in alert_type:
        return ["BlockIp", "Notify"]
    if "brute" in alert_type or "auth" in alert_type:
        return ["BlockIp", "OpenTicket"]
    if "malware" in alert_type or "ransom" in alert_type:
        return ["IsolateHost", "CollectForensics", "OpenTicket"]
    if "exfil" in alert_type:
        return ["CollectForensics", "Notify", "OpenTicket"]
    return ["Notify", "OpenTicket"]


def _build_action_parameters(action_type: str, entities: Dict) -> Dict[str, str]:
    parameters: Dict[str, str] = {}
    if action_type in {"BlockIp", "UnblockIp"}:
        ip = entities.get("src_ip") or entities.get("dest_ip")
        if ip:
            parameters["src_ip"] = str(ip)
    if action_type in {"IsolateHost", "UnisolateHost", "CollectForensics"}:
        host = entities.get("hostname") or entities.get("host")
        host_id = entities.get("host_id")
        if host:
            parameters["hostname"] = str(host)
        if host_id:
            parameters["host_id"] = str(host_id)
    if action_type in {"DisableUser", "EnableUser"}:
        user = entities.get("username") or entities.get("user")
        if user:
            parameters["username"] = str(user)
    if action_type == "KillProcess":
        process = entities.get("processName") or entities.get("process")
        if process:
            parameters["processName"] = str(process)
        pid = entities.get("pid")
        if pid:
            parameters["pid"] = str(pid)
        host = entities.get("hostname") or entities.get("host")
        if host:
            parameters["hostname"] = str(host)
    if action_type == "QuarantineFile":
        file_hash = entities.get("fileHash") or entities.get("file_hash")
        if file_hash:
            parameters["fileHash"] = str(file_hash)
        file_path = entities.get("filePath") or entities.get("file_path")
        if file_path:
            parameters["filePath"] = str(file_path)
        host = entities.get("hostname") or entities.get("host")
        if host:
            parameters["hostname"] = str(host)
    return parameters


def _normalize_scoring_response(response: Dict, alert: Dict) -> Dict:
    fallback = _build_assessment(alert)
    severity = _coerce_int(response.get("severity"), int(fallback["severity"]))
    confidence = _coerce_float(response.get("confidence"), fallback["confidence"])
    severity = int(_clamp(severity, 0, 100))
    confidence = _clamp(confidence or 0.0, 0.05, 1.0)

    hypothesis = response.get("hypothesis") or fallback["hypothesis"]
    if not isinstance(hypothesis, str):
        hypothesis = str(hypothesis)

    evidence = response.get("evidence") or fallback["evidence"]
    if isinstance(evidence, str):
        evidence = [evidence]
    if not isinstance(evidence, list):
        evidence = fallback["evidence"]
    evidence = [str(item) for item in evidence][:8]

    recommended = response.get("recommendedActions") or fallback["recommendedActions"]
    if isinstance(recommended, str):
        recommended = [recommended]
    if not isinstance(recommended, list):
        recommended = []
    normalized_actions = []
    for item in recommended:
        normalized = _normalize_enum(item, ACTION_TYPES)
        if normalized:
            normalized_actions.append(normalized)
    recommended = normalized_actions[:6]

    return {
        "severity": severity,
        "confidence": round(confidence, 3),
        "hypothesis": hypothesis,
        "evidence": evidence,
        "recommendedActions": recommended,
    }


def _normalize_action(action: Dict, idx: int, alert: Dict) -> Optional[Dict]:
    action_type = _normalize_enum(action.get("type") or action.get("actionType"), ACTION_TYPES)
    if action_type is None:
        return None

    defaults = ACTION_DEFAULTS.get(action_type, {"risk": 25, "impact": 25, "reversible": False})
    risk = _coerce_int(action.get("risk"), defaults["risk"])
    impact = _coerce_int(action.get("expectedImpact"), defaults["impact"])
    reversible = _coerce_bool(action.get("reversible"), defaults["reversible"])

    duration = action.get("durationSeconds")
    duration = _coerce_int(duration, 0) if duration is not None else 0
    if duration <= 0:
        duration = None

    action_id = action.get("actionId") or f"{action_type.lower()}-{idx}"

    parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    parameters = {str(k): str(v) for k, v in parameters.items() if v not in (None, "")}
    if not parameters:
        parameters = _build_action_parameters(action_type, alert.get("entities", {}))

    rationale = action.get("rationale") or f"Auto action: {action_type}"
    if not isinstance(rationale, str):
        rationale = str(rationale)

    return {
        "actionId": str(action_id),
        "type": action_type,
        "risk": int(_clamp(risk, 0, 100)),
        "expectedImpact": int(_clamp(impact, 0, 100)),
        "reversible": bool(reversible),
        "durationSeconds": duration,
        "parameters": parameters,
        "rationale": rationale,
    }


def _build_fallback_plan(alert: Dict, assessment: Dict) -> Dict:
    severity = _coerce_int(alert.get("severity"), 50)
    strategy = _default_strategy(severity)
    action_types = _default_actions(alert)

    actions = []
    for idx, action_type in enumerate(action_types, start=1):
        defaults = ACTION_DEFAULTS[action_type]
        action = {
            "actionId": f"{action_type.lower()}-{idx}",
            "type": action_type,
            "risk": defaults["risk"],
            "expectedImpact": defaults["impact"],
            "reversible": defaults["reversible"],
            "durationSeconds": 3600 if defaults["reversible"] and action_type in {"BlockIp", "IsolateHost"} else None,
            "parameters": _build_action_parameters(action_type, alert.get("entities", {})),
            "rationale": f"Fallback action for {alert.get('type', 'alert')}",
        }
        actions.append(action)

    rollbacks = []
    for idx, action in enumerate(actions, start=1):
        if action["reversible"]:
            rollback_type = ROLLBACK_MAP.get(action["type"])
            if rollback_type:
                rollback = {
                    "actionId": f"{rollback_type.lower()}-{idx}",
                    "type": rollback_type,
                    "risk": ACTION_DEFAULTS[rollback_type]["risk"],
                    "expectedImpact": ACTION_DEFAULTS[rollback_type]["impact"],
                    "reversible": False,
                    "durationSeconds": None,
                    "parameters": action["parameters"],
                    "rationale": f"Rollback for {action['type']}",
                }
                rollbacks.append(rollback)

    return {
        "planId": uuid4().hex,
        "strategy": strategy,
        "priority": int(_clamp(severity, 0, 100)),
        "summary": f"Strategy={strategy}, Severity={severity}, Confidence={assessment.get('confidence')}",
        "actions": actions,
        "rollbackActions": rollbacks,
        "rationale": [
            f"Strategy {strategy} based on severity {severity}.",
            f"Dataset {alert.get('context', {}).get('dataset', 'unknown')}.",
        ],
        "tags": {
            "dataset": str(alert.get("context", {}).get("dataset", "unknown")),
            "generatedBy": "llm_dataset_pipeline",
        },
    }


def _normalize_plan_response(response: Dict, alert: Dict, assessment: Dict) -> Dict:
    payload = response.get("plan") if isinstance(response.get("plan"), dict) else response
    if not isinstance(payload, dict):
        payload = {}

    actions_raw = payload.get("actions")
    if not isinstance(actions_raw, list):
        actions_raw = []

    normalized_actions = []
    for idx, action in enumerate(actions_raw, start=1):
        if isinstance(action, dict):
            normalized = _normalize_action(action, idx, alert)
            if normalized:
                normalized_actions.append(normalized)

    if not normalized_actions:
        return _build_fallback_plan(alert, assessment)

    rollbacks_raw = payload.get("rollbackActions")
    normalized_rollbacks = []
    if isinstance(rollbacks_raw, list):
        for idx, action in enumerate(rollbacks_raw, start=1):
            if isinstance(action, dict):
                normalized = _normalize_action(action, idx, alert)
                if normalized:
                    normalized_rollbacks.append(normalized)

    if not normalized_rollbacks:
        for idx, action in enumerate(normalized_actions, start=1):
            if action.get("reversible"):
                rollback_type = ROLLBACK_MAP.get(action["type"])
                if rollback_type:
                    rollback = {
                        "actionId": f"{rollback_type.lower()}-{idx}",
                        "type": rollback_type,
                        "risk": ACTION_DEFAULTS[rollback_type]["risk"],
                        "expectedImpact": ACTION_DEFAULTS[rollback_type]["impact"],
                        "reversible": False,
                        "durationSeconds": None,
                        "parameters": action.get("parameters", {}),
                        "rationale": f"Rollback for {action['type']}",
                    }
                    normalized_rollbacks.append(rollback)

    severity = _coerce_int(alert.get("severity"), 50)
    strategy = _normalize_enum(payload.get("strategy"), PLAN_STRATEGIES) or _default_strategy(severity)
    priority = _coerce_int(payload.get("priority"), int(_clamp(severity, 0, 100)))
    summary = payload.get("summary") or f"Strategy={strategy}, Severity={severity}, Confidence={assessment.get('confidence')}"

    rationale = payload.get("rationale")
    if not isinstance(rationale, list):
        rationale = [f"Strategy {strategy} based on severity {severity}."]
    rationale = [str(item) for item in rationale][:8]

    tags = payload.get("tags") if isinstance(payload.get("tags"), dict) else {}
    tags = {str(k): str(v) for k, v in tags.items()}
    tags.setdefault("dataset", str(alert.get("context", {}).get("dataset", "unknown")))
    tags.setdefault("generatedBy", "llm_dataset_pipeline")

    return {
        "planId": str(payload.get("planId") or uuid4().hex),
        "strategy": strategy,
        "priority": int(_clamp(priority, 0, 100)),
        "summary": str(summary),
        "actions": normalized_actions,
        "rollbackActions": normalized_rollbacks,
        "rationale": rationale,
        "tags": tags,
    }

def generate_dataset(
    alerts: List[AlertRecord],
    output: Path,
    llm_client: OllamaClient,
    mode: str,
    temperature: float,
    max_tokens: int,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    random.shuffle(alerts)

    with output.open("w", encoding="utf-8") as handle:
        for alert_record in alerts:
            for stream in ("scorer", "planner"):
                if mode != "both" and stream != mode:
                    continue

                if stream == "scorer":
                    messages = _build_scoring_messages(alert_record.alert)
                else:
                    messages = _build_plan_messages(alert_record.alert)

                system = messages[0]["content"]
                user = messages[1]["content"]

                response_text = llm_client.generate(
                    prompt=user,
                    system=system,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                response_json = _extract_json(response_text)

                if stream == "scorer":
                    normalized = _normalize_scoring_response(response_json, alert_record.alert)
                else:
                    assessment = _build_assessment(alert_record.alert)
                    normalized = _normalize_plan_response(response_json, alert_record.alert, assessment)

                record = {
                    "messages": messages + [{"role": "assistant", "content": json.dumps(normalized)}],
                    "meta": {
                        "source": alert_record.source,
                        "source_file": alert_record.source_file,
                        "record_id": alert_record.record_id,
                        "stream": stream,
                    },
                }
                handle.write(json.dumps(record) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="LLM-assisted dataset generation pipeline")
    parser.add_argument("--source-root", type=Path, default=Path("data/external"))
    parser.add_argument("--output", type=Path, default=Path("training_data.jsonl"))
    parser.add_argument("--max-records", type=int, default=60)
    parser.add_argument("--max-file-mb", type=int, default=512)
    parser.add_argument("--mode", choices=["scorer", "planner", "both"], default="both")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--ollama-model", default="baronllm-q6k")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--max-tokens", type=int, default=512)

    args = parser.parse_args()

    alerts = load_alerts_from_sources(args.source_root, args.max_records, args.max_file_mb)
    if not alerts:
        raise RuntimeError(
            f"No alerts found. Ensure datasets exist under {args.source_root}."
        )

    client = OllamaClient(args.ollama_url, args.ollama_model, timeout=120)
    generate_dataset(
        alerts=alerts,
        output=args.output,
        llm_client=client,
        mode=args.mode,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
    )


if __name__ == "__main__":
    main()
