"""
LLM-assisted dataset generation from real security data sources.

Reads real attack patterns from:
  - MITRE ATT&CK STIX (technique descriptions, tactics, procedures)
  - Mordor / Security-Datasets (real Windows event logs from attack simulations)
  - CIC-IDS2018 (network flow data with attack labels)

Converts them into SOAR-compatible alerts, then calls Ollama to generate
scorer and planner completions. Outputs JSONL for human review.

Usage:
    python -m intelligence.training.generate_from_real_data \
        --datasets-dir datasets \
        --output-dir intelligence/training/data \
        --ollama-url http://localhost:11434 \
        --ollama-model baron-security \
        --count 200
"""

import argparse
import csv
import json
import logging
import random
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ---------------------------------------------------------------------------
# Prompt builders (identical to production)
# ---------------------------------------------------------------------------

def build_scorer_prompt(alert: Dict[str, Any]) -> str:
    return (
        "You are a SOC threat scoring assistant. "
        "Return ONLY a JSON object with these fields:\n"
        "- severity: integer 0-100 (0=benign noise, 30=low, 50=medium, 70=high, 90+=critical)\n"
        "- confidence: float 0.0-1.0 (how certain you are in your assessment; "
        "use >=0.70 when the alert clearly matches a known attack pattern, "
        "0.40-0.69 when uncertain, <0.40 for likely benign/noise)\n"
        "- hypothesis: one-sentence explanation of what is happening\n"
        "- evidence: array of 1-3 short strings listing key indicators\n\n"
        "IMPORTANT: confidence >= 0.60 allows automated response actions. "
        "Only give high confidence when the alert data clearly indicates a real threat.\n\n"
        f"Alert:\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n"
    )


def build_planner_prompt(alert: Dict[str, Any], assessment: Dict[str, Any]) -> str:
    schema_hint = {
        "planId": "string",
        "strategy": "ObserveMore|NotifyOnly|Contain|ContainAndCollect|EscalateToHuman",
        "priority": "0-100 int",
        "summary": "string",
        "actions": [
            {
                "type": "<ActionType>",
                "risk": "0-100 int",
                "expectedImpact": "0-100 int",
                "reversible": "true|false",
                "parameters": {"<exact_key>": "<value_from_alert>"},
                "rationale": "string",
            }
        ],
        "rollbackActions": [],
        "rationale": ["string"],
        "tags": {"key": "value"},
    }

    entities = alert.get("entities", {})
    if not isinstance(entities, dict):
        entities = {}
    available = {k: v for k, v in entities.items() if v}

    action_catalog = (
        "ACTION TYPES AND THEIR REQUIRED PARAMETER KEYS:\n"
        '- BlockIp: requires {"src_ip": "<ip_address>"}\n'
        '- UnblockIp: requires {"src_ip": "<ip_address>"}\n'
        '- IsolateHost: requires {"host_id": "<id>"} (optionally "hostname")\n'
        '- UnisolateHost: requires {"host_id": "<id>"} (optionally "hostname")\n'
        '- DisableUser: requires {"username": "<name>"} (optionally "user_id")\n'
        '- EnableUser: requires {"username": "<name>"} (optionally "user_id")\n'
        '- KillProcess: requires {"host_id": "<id>", "process_name": "<name>"}\n'
        '- QuarantineFile: requires {"host_id": "<id>", "file_hash": "<hash>"}\n'
        "- OpenTicket: no required parameters (always safe)\n"
        "- Notify: no required parameters (always safe)\n"
        "- CollectForensics: no required parameters\n"
    )

    confidence = assessment.get("confidence", 0)
    confidence_rule = ""
    if isinstance(confidence, (int, float)) and confidence < 0.60:
        confidence_rule = (
            "\nIMPORTANT: The assessment confidence is below 0.60. "
            "Only OpenTicket and Notify actions are allowed at low confidence. "
            "Do NOT propose destructive actions (BlockIp, IsolateHost, DisableUser, "
            "KillProcess, QuarantineFile) when confidence is this low.\n"
        )

    return (
        "You are a SOC response planner. "
        "Return ONLY a JSON object matching this schema:\n"
        f"{json.dumps(schema_hint, indent=2)}\n\n"
        f"{action_catalog}\n"
        "RULES:\n"
        "1. ONLY propose actions for which you have the required entity data from the alert.\n"
        '2. Use the EXACT parameter key names listed above (e.g. "src_ip" not "source_ip").\n'
        "3. Copy entity values directly from the alert data - do not invent values.\n"
        "4. Always include at least an OpenTicket or Notify action for documentation.\n"
        "5. Keep the plan concise: 1-4 actions maximum.\n"
        f"{confidence_rule}\n"
        f"Available entity data from alert: {json.dumps(available) if available else 'NONE - only use OpenTicket/Notify'}\n\n"
        f"Alert:\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n\n"
        f"Assessment:\n{json.dumps(assessment, ensure_ascii=False, indent=2)}\n"
    )


# ---------------------------------------------------------------------------
# Ollama client
# ---------------------------------------------------------------------------

def ollama_generate(prompt: str, base_url: str, model: str, timeout: int = 120) -> Optional[str]:
    """Call Ollama /api/chat and return the assistant's message content."""
    try:
        resp = requests.post(
            f"{base_url}/api/chat",
            json={
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity SOC analyst assistant. You respond only with valid JSON matching the requested schema.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "options": {"temperature": 0.3, "num_ctx": 4096},
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("message", {}).get("content", "").strip()
    except Exception as e:
        logger.warning(f"Ollama call failed: {e}")
        return None


def extract_json(text: str) -> Optional[Dict]:
    """Extract a JSON object from text that may contain markdown fences."""
    if not text:
        return None
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try extracting from markdown code block
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Try finding first { ... } block
    depth = 0
    start = None
    for i, c in enumerate(text):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    start = None
    return None


# ---------------------------------------------------------------------------
# Source 1: MITRE ATT&CK techniques → alerts
# ---------------------------------------------------------------------------

# Map ATT&CK tactics to our alert types and severity ranges
TACTIC_MAPPING = {
    "reconnaissance": ("PortScanFromIp", (40, 65)),
    "initial-access": ("SuspiciousProcessOnHost", (55, 80)),
    "execution": ("SuspiciousProcessOnHost", (60, 85)),
    "persistence": ("MalwareHashOnHost", (65, 85)),
    "privilege-escalation": ("SuspiciousProcessOnHost", (65, 85)),
    "defense-evasion": ("SuspiciousProcessOnHost", (55, 80)),
    "credential-access": ("BruteForceUser", (60, 85)),
    "discovery": ("PortScanFromIp", (35, 60)),
    "lateral-movement": ("BruteForceUser", (65, 85)),
    "collection": ("SuspiciousProcessOnHost", (55, 75)),
    "command-and-control": ("SuspiciousProcessOnHost", (70, 90)),
    "exfiltration": ("SuspiciousProcessOnHost", (75, 95)),
    "impact": ("MalwareHashOnHost", (80, 95)),
}


def load_mitre_techniques(datasets_dir: Path, rng: random.Random, max_count: int = 200) -> List[Dict[str, Any]]:
    """Load MITRE ATT&CK technique descriptions and convert to alerts."""
    attack_dir = datasets_dir / "mitre-attack" / "enterprise-attack" / "attack-pattern"
    if not attack_dir.exists():
        logger.warning(f"MITRE ATT&CK not found at {attack_dir}")
        return []

    alerts = []
    technique_files = list(attack_dir.glob("*.json"))
    rng.shuffle(technique_files)

    for fpath in technique_files[:max_count * 2]:  # read more, filter later
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            objects = data.get("objects", [])
            technique = None
            for obj in objects:
                if obj.get("type") == "attack-pattern":
                    technique = obj
                    break
            if not technique:
                continue

            name = technique.get("name", "Unknown")
            desc = technique.get("description", "")[:500]
            platforms = technique.get("x_mitre_platforms", ["Windows"])
            ext_refs = technique.get("external_references", [])
            technique_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break

            # Determine tactic from kill chain
            tactics = []
            for phase in technique.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase["phase_name"])

            if not tactics:
                continue

            primary_tactic = rng.choice(tactics)
            alert_type, severity_range = TACTIC_MAPPING.get(
                primary_tactic, ("SuspiciousProcessOnHost", (50, 75))
            )

            # Build realistic alert based on technique
            alert = _build_mitre_alert(alert_type, name, technique_id, desc, primary_tactic, severity_range, rng)
            alert["_source"] = "mitre-attack"
            alert["_technique_id"] = technique_id
            alert["_technique_name"] = name
            alert["_tactic"] = primary_tactic
            alert["_description"] = desc
            alerts.append(alert)

            if len(alerts) >= max_count:
                break
        except Exception as e:
            logger.debug(f"Skipping {fpath.name}: {e}")
            continue

    logger.info(f"Loaded {len(alerts)} alerts from MITRE ATT&CK techniques")
    return alerts


def _build_mitre_alert(
    alert_type: str, technique_name: str, technique_id: str,
    description: str, tactic: str, severity_range: Tuple[int, int],
    rng: random.Random
) -> Dict[str, Any]:
    """Convert a MITRE technique into a SOAR alert."""
    severity = rng.randint(*severity_range)

    # Generate realistic entity data based on alert type
    if alert_type == "PortScanFromIp":
        src_ip = f"10.{rng.randint(0,255)}.{rng.randint(1,254)}.{rng.randint(1,254)}"
        entities = {"srcIp": src_ip}
        raw_payload = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "src_ip": src_ip,
            "description": description[:200],
        }
        rule_name = f"MITRE_{technique_id}_{tactic}"
    elif alert_type == "BruteForceUser":
        src_ip = f"172.16.{rng.randint(1,254)}.{rng.randint(1,254)}"
        username = rng.choice(["admin", "root", "svc_account", "domain_admin", "backup_user", f"user{rng.randint(1,50)}"])
        entities = {"srcIp": src_ip, "username": username, "userId": f"u-{rng.randint(1000,9999)}"}
        raw_payload = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "username": username,
            "src_ip": src_ip,
            "failed_logins": rng.randint(5, 200),
            "description": description[:200],
        }
        rule_name = f"MITRE_{technique_id}_{tactic}"
    elif alert_type == "MalwareHashOnHost":
        host_id = f"host-{rng.randint(100,999)}"
        file_hash = uuid.uuid4().hex
        entities = {"hostId": host_id, "fileHash": file_hash}
        raw_payload = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "host_id": host_id,
            "file_hash": file_hash,
            "description": description[:200],
        }
        rule_name = f"MITRE_{technique_id}_{tactic}"
    else:  # SuspiciousProcessOnHost
        host_id = f"host-{rng.randint(100,999)}"
        proc = rng.choice([
            "powershell.exe", "cmd.exe", "certutil.exe", "mshta.exe",
            "wscript.exe", "regsvr32.exe", "rundll32.exe", "cscript.exe",
            "bitsadmin.exe", "msiexec.exe", "schtasks.exe", "wmic.exe",
        ])
        entities = {"hostId": host_id, "processName": proc}
        raw_payload = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "host_id": host_id,
            "process_name": proc,
            "pid": rng.randint(1000, 65535),
            "description": description[:200],
        }
        rule_name = f"MITRE_{technique_id}_{tactic}"

    return {
        "sourceSiem": "mitre-attack",
        "alertId": uuid.uuid4().hex,
        "type": alert_type,
        "ruleName": rule_name,
        "severity": severity,
        "entities": entities,
        "rawPayload": raw_payload,
    }


# ---------------------------------------------------------------------------
# Source 2: Mordor event logs → alerts
# ---------------------------------------------------------------------------

# Sysmon event ID to alert type mapping
SYSMON_EVENT_MAPPING = {
    1: ("SuspiciousProcessOnHost", "Process creation"),
    3: ("PortScanFromIp", "Network connection"),
    7: ("SuspiciousProcessOnHost", "Image loaded"),
    8: ("SuspiciousProcessOnHost", "CreateRemoteThread"),
    10: ("SuspiciousProcessOnHost", "Process access"),
    11: ("MalwareHashOnHost", "File created"),
    12: ("SuspiciousProcessOnHost", "Registry event"),
    13: ("SuspiciousProcessOnHost", "Registry value set"),
    15: ("MalwareHashOnHost", "File stream created"),
    22: ("PortScanFromIp", "DNS query"),
}

# Windows Security event ID mapping
SECURITY_EVENT_MAPPING = {
    4624: ("BruteForceUser", "Successful logon"),
    4625: ("BruteForceUser", "Failed logon"),
    4648: ("BruteForceUser", "Logon with explicit credentials"),
    4672: ("SuspiciousProcessOnHost", "Special privileges assigned"),
    4688: ("SuspiciousProcessOnHost", "Process created"),
    4720: ("BruteForceUser", "User account created"),
    4728: ("BruteForceUser", "Member added to security group"),
    4732: ("BruteForceUser", "Member added to local group"),
    5156: ("PortScanFromIp", "Windows Filtering Platform connection"),
}


def load_mordor_events(datasets_dir: Path, rng: random.Random, max_count: int = 200) -> List[Dict[str, Any]]:
    """Load Mordor event logs and convert to SOAR alerts."""
    mordor_dir = datasets_dir / "mordor" / "datasets"
    if not mordor_dir.exists():
        logger.warning(f"Mordor datasets not found at {mordor_dir}")
        return []

    # Find JSON event files (including extracted ZIPs in _extracted/)
    json_files = list(mordor_dir.rglob("*.json"))
    if not json_files:
        logger.warning("No JSON event files found in Mordor datasets")
        return []

    rng.shuffle(json_files)
    alerts = []
    seen_types = set()

    for fpath in json_files:
        if len(alerts) >= max_count:
            break

        try:
            # Mordor files are newline-delimited JSON
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            if not lines:
                continue

            # Sample a subset of events from this file
            sample_lines = rng.sample(lines, min(len(lines), 20))

            for line in sample_lines:
                if len(alerts) >= max_count:
                    break
                try:
                    event = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue

                alert = _mordor_event_to_alert(event, fpath.stem, rng)
                if alert:
                    alert["_source"] = "mordor"
                    alert["_source_file"] = fpath.name
                    alerts.append(alert)

        except Exception as e:
            logger.debug(f"Skipping {fpath.name}: {e}")
            continue

    logger.info(f"Loaded {len(alerts)} alerts from Mordor event logs")
    return alerts


def _mordor_event_to_alert(event: Dict, source_file: str, rng: random.Random) -> Optional[Dict[str, Any]]:
    """Convert a single Mordor event log entry into a SOAR alert."""
    event_id = event.get("EventID")
    if isinstance(event_id, dict):
        event_id = event_id.get("Value", event_id.get("value"))
    if event_id is None:
        return None

    try:
        event_id = int(event_id)
    except (ValueError, TypeError):
        return None

    # Determine alert type from event ID
    source_name = event.get("SourceName", event.get("source_name", ""))
    if "Sysmon" in str(source_name):
        mapping = SYSMON_EVENT_MAPPING
    else:
        mapping = SECURITY_EVENT_MAPPING

    if event_id not in mapping:
        return None

    alert_type, event_desc = mapping[event_id]

    # Extract entities from event data
    src_ip = (
        event.get("SourceAddress")
        or event.get("IpAddress")
        or event.get("SourceIp")
        or event.get("src_ip")
    )
    hostname = (
        event.get("Computer")
        or event.get("Hostname")
        or event.get("hostname")
    )
    username = (
        event.get("TargetUserName")
        or event.get("AccountName")
        or event.get("UserName")
        or event.get("SubjectUserName")
    )
    process_name = (
        event.get("Image")
        or event.get("NewProcessName")
        or event.get("process_name")
    )
    if process_name and "\\" in str(process_name):
        process_name = str(process_name).split("\\")[-1]

    file_hash = event.get("Hashes", event.get("Hash", ""))
    if isinstance(file_hash, str) and "=" in file_hash:
        # Sysmon format: "SHA256=abc123,MD5=def456"
        parts = file_hash.split(",")
        for part in parts:
            if part.startswith("SHA256="):
                file_hash = part.split("=", 1)[1]
                break
            elif part.startswith("MD5="):
                file_hash = part.split("=", 1)[1]
                break

    # Filter out empty/system values
    if src_ip in (None, "", "::1", "-", "127.0.0.1", "0.0.0.0"):
        src_ip = None
    if username in (None, "", "-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1"):
        username = None
    if hostname in (None, ""):
        hostname = None

    # Need at least one meaningful entity
    entities = {}
    if src_ip:
        entities["srcIp"] = str(src_ip)
    if hostname:
        host_id = str(hostname).split(".")[0].lower()
        entities["hostId"] = host_id
        entities["hostname"] = str(hostname)
    if username:
        entities["username"] = str(username)
    if process_name:
        entities["processName"] = str(process_name)
    if file_hash and len(str(file_hash)) > 10:
        entities["fileHash"] = str(file_hash)

    if not entities:
        return None

    # Determine severity based on event type
    severity_map = {
        "SuspiciousProcessOnHost": rng.randint(50, 80),
        "BruteForceUser": rng.randint(55, 85),
        "MalwareHashOnHost": rng.randint(70, 95),
        "PortScanFromIp": rng.randint(35, 65),
    }

    # Build raw payload from actual event fields
    raw_payload = {}
    for key in ["EventID", "SourceName", "Category", "Message", "CommandLine",
                 "ParentImage", "ParentCommandLine", "TargetFilename",
                 "DestPort", "DestinationIp", "Protocol", "LogonType"]:
        val = event.get(key)
        if val and str(val) not in ("", "-"):
            raw_payload[key] = str(val)[:200]

    return {
        "sourceSiem": "mordor",
        "alertId": uuid.uuid4().hex,
        "type": alert_type,
        "ruleName": f"Mordor_EID{event_id}_{event_desc.replace(' ', '')}",
        "severity": severity_map.get(alert_type, 50),
        "entities": entities,
        "rawPayload": raw_payload,
    }


# ---------------------------------------------------------------------------
# Source 3: CIC-IDS2018 network flows → alerts
# ---------------------------------------------------------------------------

CIC_LABEL_MAPPING = {
    "Benign": ("BenignNoise", (5, 20)),
    "FTP-BruteForce": ("BruteForceUser", (60, 80)),
    "SSH-Bruteforce": ("BruteForceUser", (65, 85)),
    "Brute Force -Web": ("BruteForceUser", (55, 75)),
    "Brute Force -XSS": ("BruteForceUser", (60, 80)),
    "SQL Injection": ("SuspiciousProcessOnHost", (70, 90)),
    "Bot": ("MalwareHashOnHost", (75, 90)),
    "DoS attacks-Hulk": ("PortScanFromIp", (65, 85)),
    "DoS attacks-SlowHTTPTest": ("PortScanFromIp", (60, 80)),
    "DoS attacks-Slowloris": ("PortScanFromIp", (60, 80)),
    "DoS attacks-GoldenEye": ("PortScanFromIp", (65, 85)),
    "DDoS attacks-LOIC-HTTP": ("PortScanFromIp", (70, 90)),
    "DDoS attack-HOIC": ("PortScanFromIp", (70, 90)),
    "DDoS attack-LOIC-UDP": ("PortScanFromIp", (70, 90)),
    "Infilteration": ("SuspiciousProcessOnHost", (70, 90)),
    "DDOS attack-HOIC": ("PortScanFromIp", (70, 90)),
}


def load_cicids_flows(datasets_dir: Path, rng: random.Random, max_count: int = 200) -> List[Dict[str, Any]]:
    """Load CIC-IDS2018 CSV flows and convert attack entries to alerts."""
    cic_dir = datasets_dir / "cic-ids"
    csv_files = list(cic_dir.glob("*.csv"))
    if not csv_files:
        logger.warning(f"No CIC-IDS CSV files found in {cic_dir}")
        return []

    # Collect attack rows from all CSVs first, then sample
    attack_rows = []
    benign_rows = []

    for csv_path in csv_files:
        logger.info(f"Reading {csv_path.name}...")
        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    label = row.get("Label", "").strip()
                    if not label or label == "Label":
                        continue
                    if label != "Benign":
                        attack_rows.append((row, csv_path.stem))
                    elif rng.random() < 0.03:
                        benign_rows.append((row, csv_path.stem))
                    if len(attack_rows) >= max_count * 10:
                        break
        except Exception as e:
            logger.warning(f"Error reading {csv_path.name}: {e}")
            continue

    logger.info(f"CIC-IDS raw: {len(attack_rows)} attack rows, {len(benign_rows)} benign rows")

    # Target: 80% attack, 20% benign
    attack_target = int(max_count * 0.8)
    benign_target = max_count - attack_target

    rng.shuffle(attack_rows)
    rng.shuffle(benign_rows)

    alerts = []
    for row, stem in attack_rows[:attack_target]:
        alert = _cicids_flow_to_alert(row, stem, rng)
        if alert:
            alert["_source"] = "cic-ids"
            alert["_source_file"] = stem
            alerts.append(alert)

    for row, stem in benign_rows[:benign_target]:
        alert = _cicids_flow_to_alert(row, stem, rng)
        if alert:
            alert["_source"] = "cic-ids"
            alert["_source_file"] = stem
            alerts.append(alert)

    logger.info(f"Loaded {len(alerts)} alerts from CIC-IDS2018 flows")
    return alerts


def _cicids_flow_to_alert(row: Dict[str, str], source_file: str, rng: random.Random) -> Optional[Dict[str, Any]]:
    """Convert a CIC-IDS2018 flow record into a SOAR alert.

    CIC-IDS2018 CSVs contain flow-level features (no raw IPs in most versions).
    We generate synthetic IPs and use the flow statistics as context.
    """
    label = row.get("Label", "").strip()
    if not label or label == "Label":
        return None

    alert_type, severity_range = CIC_LABEL_MAPPING.get(label, ("SuspiciousProcessOnHost", (50, 75)))

    # CIC-IDS CSVs have Dst Port, Protocol, Timestamp, and flow features but not always IPs
    dst_port = row.get("Dst Port", "").strip()
    protocol = row.get("Protocol", "").strip()
    timestamp = row.get("Timestamp", "").strip()

    # Generate synthetic IPs for the alert (real IPs not in processed CSVs)
    src_ip = f"10.{rng.randint(0,255)}.{rng.randint(1,254)}.{rng.randint(1,254)}"
    dst_ip = f"192.168.{rng.randint(1,254)}.{rng.randint(1,254)}"

    entities = {"srcIp": src_ip}

    # Build raw payload from flow features
    raw_payload = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "label": label,
        "timestamp": timestamp,
    }

    # Add key flow statistics that provide attack context
    for key in ["Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
                 "Flow Byts/s", "Flow Pkts/s", "Fwd Pkts/s", "Bwd Pkts/s",
                 "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt"]:
        val = row.get(key, "").strip()
        if val and val not in ("", "0", "NaN", "Infinity"):
            raw_payload[key.replace(" ", "_").replace("/", "_per_").lower()] = val

    # Determine rule name from label
    rule_name = label.replace(" ", "").replace("-", "")

    if alert_type == "BruteForceUser":
        username = rng.choice(["admin", "root", "ftp_user", "ssh_user", f"user{rng.randint(1,50)}"])
        entities["username"] = username
        raw_payload["username"] = username

    return {
        "sourceSiem": "cic-ids",
        "alertId": uuid.uuid4().hex,
        "type": alert_type,
        "ruleName": f"CIC_{rule_name}",
        "severity": rng.randint(*severity_range),
        "entities": entities,
        "rawPayload": raw_payload,
    }


# ---------------------------------------------------------------------------
# LLM-assisted generation pipeline
# ---------------------------------------------------------------------------

def generate_training_pair(
    alert: Dict[str, Any],
    base_url: str,
    model: str,
    timeout: int = 120,
) -> Optional[Tuple[Dict, Dict]]:
    """
    Generate a scorer + planner training pair for one alert using Ollama.

    Returns (scorer_example, planner_example) or None if generation failed.
    """
    # Remove internal metadata fields before sending to LLM
    clean_alert = {k: v for k, v in alert.items() if not k.startswith("_")}

    # Step 1: Generate scorer completion
    scorer_prompt = build_scorer_prompt(clean_alert)
    scorer_raw = ollama_generate(scorer_prompt, base_url, model, timeout)
    scorer_result = extract_json(scorer_raw) if scorer_raw else None

    if not scorer_result:
        logger.debug(f"Scorer generation failed for alert {alert.get('alertId', '?')}")
        return None

    # Validate scorer output
    if not all(k in scorer_result for k in ("severity", "confidence", "hypothesis", "evidence")):
        logger.debug(f"Scorer output missing required fields: {list(scorer_result.keys())}")
        return None

    # Step 2: Generate planner completion using the scorer result
    planner_prompt = build_planner_prompt(clean_alert, scorer_result)
    planner_raw = ollama_generate(planner_prompt, base_url, model, timeout)
    planner_result = extract_json(planner_raw) if planner_raw else None

    if not planner_result:
        logger.debug(f"Planner generation failed for alert {alert.get('alertId', '?')}")
        return None

    # Validate planner output
    if not all(k in planner_result for k in ("planId", "strategy", "actions")):
        logger.debug(f"Planner output missing required fields: {list(planner_result.keys())}")
        return None

    # Build training examples
    scorer_example = {
        "prompt": scorer_prompt,
        "completion": json.dumps(scorer_result, ensure_ascii=False),
        "source": alert.get("_source", "unknown"),
        "alert_type": alert.get("type", "unknown"),
        "technique_id": alert.get("_technique_id", ""),
    }

    planner_example = {
        "prompt": planner_prompt,
        "completion": json.dumps(planner_result, ensure_ascii=False),
        "source": alert.get("_source", "unknown"),
        "alert_type": alert.get("type", "unknown"),
        "technique_id": alert.get("_technique_id", ""),
    }

    return scorer_example, planner_example


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate training data from real security datasets + Ollama.")
    parser.add_argument("--datasets-dir", type=Path, default=Path("datasets"), help="Root datasets directory.")
    parser.add_argument("--output-dir", type=Path, default=Path("intelligence/training/data"), help="Output directory.")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama API base URL.")
    parser.add_argument("--ollama-model", default="baron-security", help="Ollama model name.")
    parser.add_argument("--ollama-timeout", type=int, default=120, help="Ollama request timeout in seconds.")
    parser.add_argument("--count", type=int, default=200, help="Target number of examples per source.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    parser.add_argument("--skip-ollama", action="store_true", help="Only generate alerts, skip LLM scoring/planning.")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Load alerts from all sources
    logger.info("=" * 60)
    logger.info("Loading alerts from real security datasets...")
    logger.info("=" * 60)

    all_alerts = []

    mitre_alerts = load_mitre_techniques(args.datasets_dir, rng, args.count)
    all_alerts.extend(mitre_alerts)

    mordor_alerts = load_mordor_events(args.datasets_dir, rng, args.count)
    all_alerts.extend(mordor_alerts)

    cicids_alerts = load_cicids_flows(args.datasets_dir, rng, args.count)
    all_alerts.extend(cicids_alerts)

    rng.shuffle(all_alerts)
    logger.info(f"Total alerts: {len(all_alerts)}")

    # Save raw alerts for inspection
    alerts_path = args.output_dir / "real_alerts.jsonl"
    with open(alerts_path, "w", encoding="utf-8") as f:
        for alert in all_alerts:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")
    logger.info(f"Raw alerts saved: {alerts_path}")

    if args.skip_ollama:
        logger.info("--skip-ollama set, skipping LLM generation. Review alerts in real_alerts.jsonl.")
        # Print distribution
        sources = {}
        types = {}
        for a in all_alerts:
            s = a.get("_source", "unknown")
            t = a.get("type", "unknown")
            sources[s] = sources.get(s, 0) + 1
            types[t] = types.get(t, 0) + 1
        logger.info(f"By source: {json.dumps(sources)}")
        logger.info(f"By type: {json.dumps(types)}")
        return

    # Generate training pairs using Ollama
    logger.info("=" * 60)
    logger.info(f"Generating training pairs with Ollama ({args.ollama_model})...")
    logger.info("=" * 60)

    scorer_data = []
    planner_data = []
    failed = 0

    for i, alert in enumerate(all_alerts):
        if (i + 1) % 10 == 0:
            logger.info(f"Progress: {i + 1}/{len(all_alerts)} (scorer={len(scorer_data)}, planner={len(planner_data)}, failed={failed})")

        result = generate_training_pair(alert, args.ollama_url, args.ollama_model, args.ollama_timeout)
        if result:
            scorer_ex, planner_ex = result
            scorer_data.append(scorer_ex)
            planner_data.append(planner_ex)
        else:
            failed += 1

    # Save training data
    scorer_path = args.output_dir / "real_scorer_train.jsonl"
    planner_path = args.output_dir / "real_planner_train.jsonl"

    with open(scorer_path, "w", encoding="utf-8") as f:
        for item in scorer_data:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    with open(planner_path, "w", encoding="utf-8") as f:
        for item in planner_data:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    logger.info("=" * 60)
    logger.info("GENERATION COMPLETE")
    logger.info("=" * 60)
    logger.info(f"Scorer examples: {len(scorer_data)} -> {scorer_path}")
    logger.info(f"Planner examples: {len(planner_data)} -> {planner_path}")
    logger.info(f"Failed: {failed}")

    # Print distribution
    sources = {}
    types = {}
    for ex in scorer_data:
        s = ex.get("source", "unknown")
        t = ex.get("alert_type", "unknown")
        sources[s] = sources.get(s, 0) + 1
        types[t] = types.get(t, 0) + 1
    logger.info(f"By source: {json.dumps(sources)}")
    logger.info(f"By type: {json.dumps(types)}")
    logger.info(f"\nReview files before training:")
    logger.info(f"  {scorer_path}")
    logger.info(f"  {planner_path}")


if __name__ == "__main__":
    main()
