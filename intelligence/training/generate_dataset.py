"""
Generate synthetic training data for SOAR scorer and planner fine-tuning.

Produces two JSONL files:
  - scorer_train.jsonl  (prompt/completion pairs for threat scoring)
  - planner_train.jsonl (prompt/completion pairs for response planning)

Each example uses the same prompt format as the production scorer/planner prompts
so the fine-tuned model learns to respond in the exact schema expected by the C# engine.

Usage:
    python -m intelligence.training.generate_dataset \
        --output-dir intelligence/training/data \
        --scorer-count 600 \
        --planner-count 600
"""

import argparse
import json
import random
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Alert generators (mirrors C# ScenarioTemplates)
# ---------------------------------------------------------------------------

def _random_ip(rng: random.Random, prefix: str = "10.0") -> str:
    return f"{prefix}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def _gen_port_scan(rng: random.Random) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    src_ip = _random_ip(rng)
    attempts = rng.randint(50, 500)
    alert = {
        "sourceSiem": "simulator",
        "alertId": uuid.uuid4().hex,
        "type": "PortScanFromIp",
        "ruleName": "PortScanFromIp",
        "severity": rng.randint(40, 70),
        "entities": {
            "srcIp": src_ip,
            "dstIp": None,
            "hostname": None,
            "hostId": None,
            "username": None,
            "userId": None,
            "processName": None,
            "fileHash": None,
        },
    }
    alert["rawPayload"] = {"src_ip": src_ip, "dst_port_start": 20, "dst_port_end": 1024, "attempts": attempts}

    score = {
        "severity": rng.randint(55, 75),
        "confidence": round(rng.uniform(0.70, 0.90), 2),
        "hypothesis": "Network reconnaissance via port scanning detected from a single source IP.",
        "evidence": [f"src_ip={src_ip}", f"attempts={attempts}", "sequential port probing pattern"],
    }

    plan_actions = [
        {
            "type": "BlockIp",
            "risk": rng.randint(30, 55),
            "expectedImpact": rng.randint(40, 60),
            "reversible": True,
            "parameters": {"src_ip": src_ip},
            "rationale": "Block the scanning source IP to stop reconnaissance.",
        },
        {
            "type": "OpenTicket",
            "risk": 5,
            "expectedImpact": 10,
            "reversible": False,
            "parameters": {},
            "rationale": "Document the port scan incident for SOC review.",
        },
    ]

    plan = {
        "planId": f"portScan_{uuid.uuid4().hex[:8]}",
        "strategy": "Contain",
        "priority": rng.randint(50, 70),
        "summary": f"Block scanning IP {src_ip} and document incident.",
        "actions": plan_actions,
        "rollbackActions": [
            {
                "type": "UnblockIp",
                "risk": 10,
                "expectedImpact": 5,
                "reversible": True,
                "parameters": {"src_ip": src_ip},
                "rationale": "Unblock IP if determined to be legitimate.",
            }
        ],
        "rationale": ["Port scan detected", f"Source IP: {src_ip}", f"{attempts} connection attempts"],
        "tags": {"scenario_type": "PortScanFromIp"},
    }

    return alert, score, plan


def _gen_brute_force(rng: random.Random) -> Tuple[Dict, Dict, Dict]:
    username = f"user{rng.randint(1, 100)}"
    user_id = f"u-{rng.randint(1000, 9999)}"
    src_ip = _random_ip(rng, "172.16")
    failed = rng.randint(10, 100)
    alert = {
        "sourceSiem": "simulator",
        "alertId": uuid.uuid4().hex,
        "type": "BruteForceUser",
        "ruleName": "BruteForceUser",
        "severity": rng.randint(50, 80),
        "entities": {
            "srcIp": src_ip,
            "hostname": None,
            "hostId": None,
            "username": username,
            "userId": user_id,
            "processName": None,
            "fileHash": None,
        },
    }
    alert["rawPayload"] = {"username": username, "user_id": user_id, "src_ip": src_ip, "failed_logins": failed}

    score = {
        "severity": rng.randint(55, 80),
        "confidence": round(rng.uniform(0.70, 0.90), 2),
        "hypothesis": "Brute-force login attempt targeting a specific user account.",
        "evidence": [f"username={username}", f"failed_logins={failed}", f"src_ip={src_ip}"],
    }

    plan = {
        "planId": f"bruteForce_{uuid.uuid4().hex[:8]}",
        "strategy": "ContainAndCollect",
        "priority": rng.randint(55, 75),
        "summary": f"Disable targeted user {username} and block source IP.",
        "actions": [
            {
                "type": "DisableUser",
                "risk": rng.randint(50, 65),
                "expectedImpact": rng.randint(50, 70),
                "reversible": True,
                "parameters": {"username": username, "user_id": user_id},
                "rationale": "Disable the targeted account to prevent unauthorized access.",
            },
            {
                "type": "BlockIp",
                "risk": rng.randint(30, 50),
                "expectedImpact": rng.randint(40, 55),
                "reversible": True,
                "parameters": {"src_ip": src_ip},
                "rationale": "Block the attacking source IP.",
            },
            {
                "type": "Notify",
                "risk": 5,
                "expectedImpact": 10,
                "reversible": False,
                "parameters": {},
                "rationale": "Alert SOC team about brute-force attack.",
            },
        ],
        "rollbackActions": [
            {
                "type": "EnableUser",
                "risk": 15,
                "expectedImpact": 10,
                "reversible": True,
                "parameters": {"username": username, "user_id": user_id},
                "rationale": "Re-enable user if determined to be a false positive.",
            },
        ],
        "rationale": ["Brute-force detected", f"Target: {username}", f"{failed} failed logins from {src_ip}"],
        "tags": {"scenario_type": "BruteForceUser"},
    }

    return alert, score, plan


def _gen_malware_hash(rng: random.Random) -> Tuple[Dict, Dict, Dict]:
    host_id = f"host-{rng.randint(100, 999)}"
    file_hash = uuid.uuid4().hex
    file_path = rng.choice([r"C:\temp\evil.exe", r"C:\Users\Public\payload.dll", r"C:\Windows\Temp\dropper.bat"])
    alert = {
        "sourceSiem": "simulator",
        "alertId": uuid.uuid4().hex,
        "type": "MalwareHashOnHost",
        "ruleName": "MalwareHashOnHost",
        "severity": rng.randint(70, 95),
        "entities": {
            "srcIp": None,
            "hostname": None,
            "hostId": host_id,
            "username": None,
            "processName": None,
            "fileHash": file_hash,
        },
    }
    alert["rawPayload"] = {"host_id": host_id, "file_hash": file_hash, "file_path": file_path}

    score = {
        "severity": rng.randint(75, 95),
        "confidence": round(rng.uniform(0.80, 0.95), 2),
        "hypothesis": "Known malware hash detected on endpoint.",
        "evidence": [f"host_id={host_id}", f"file_hash={file_hash[:16]}...", f"file_path={file_path}"],
    }

    plan = {
        "planId": f"malware_{uuid.uuid4().hex[:8]}",
        "strategy": "ContainAndCollect",
        "priority": rng.randint(75, 95),
        "summary": f"Quarantine malware on {host_id} and isolate host.",
        "actions": [
            {
                "type": "QuarantineFile",
                "risk": rng.randint(60, 85),
                "expectedImpact": rng.randint(70, 90),
                "reversible": False,
                "parameters": {"host_id": host_id, "file_hash": file_hash},
                "rationale": "Quarantine the malicious file immediately.",
            },
            {
                "type": "IsolateHost",
                "risk": rng.randint(55, 75),
                "expectedImpact": rng.randint(60, 80),
                "reversible": True,
                "parameters": {"host_id": host_id},
                "rationale": "Isolate the compromised host to prevent lateral movement.",
            },
            {
                "type": "CollectForensics",
                "risk": 15,
                "expectedImpact": 30,
                "reversible": False,
                "parameters": {},
                "rationale": "Collect forensic artifacts for investigation.",
            },
            {
                "type": "OpenTicket",
                "risk": 5,
                "expectedImpact": 10,
                "reversible": False,
                "parameters": {},
                "rationale": "Create incident ticket for malware response.",
            },
        ],
        "rollbackActions": [
            {
                "type": "UnisolateHost",
                "risk": 20,
                "expectedImpact": 15,
                "reversible": True,
                "parameters": {"host_id": host_id},
                "rationale": "Restore host connectivity after remediation.",
            },
        ],
        "rationale": ["Known malware hash match", f"Affected host: {host_id}", f"File: {file_path}"],
        "tags": {"scenario_type": "MalwareHashOnHost"},
    }

    return alert, score, plan


def _gen_suspicious_process(rng: random.Random) -> Tuple[Dict, Dict, Dict]:
    host_id = f"host-{rng.randint(100, 999)}"
    proc = rng.choice(["powershell.exe", "cmd.exe", "certutil.exe", "mshta.exe", "wscript.exe", "regsvr32.exe"])
    pid = rng.randint(1000, 65535)
    alert = {
        "sourceSiem": "simulator",
        "alertId": uuid.uuid4().hex,
        "type": "SuspiciousProcessOnHost",
        "ruleName": "SuspiciousProcessOnHost",
        "severity": rng.randint(50, 75),
        "entities": {
            "srcIp": None,
            "hostname": None,
            "hostId": host_id,
            "username": None,
            "processName": proc,
            "fileHash": None,
        },
    }
    alert["rawPayload"] = {"host_id": host_id, "process_name": proc, "pid": pid}

    score = {
        "severity": rng.randint(50, 75),
        "confidence": round(rng.uniform(0.60, 0.85), 2),
        "hypothesis": f"Suspicious process '{proc}' execution detected on endpoint.",
        "evidence": [f"host_id={host_id}", f"process={proc}", f"pid={pid}"],
    }

    plan = {
        "planId": f"suspProc_{uuid.uuid4().hex[:8]}",
        "strategy": "Contain",
        "priority": rng.randint(50, 70),
        "summary": f"Kill suspicious process {proc} on {host_id}.",
        "actions": [
            {
                "type": "KillProcess",
                "risk": rng.randint(50, 85),
                "expectedImpact": rng.randint(60, 85),
                "reversible": False,
                "parameters": {"host_id": host_id, "process_name": proc},
                "rationale": f"Terminate suspicious process {proc}.",
            },
            {
                "type": "Notify",
                "risk": 5,
                "expectedImpact": 10,
                "reversible": False,
                "parameters": {},
                "rationale": "Alert SOC team about suspicious process execution.",
            },
        ],
        "rollbackActions": [],
        "rationale": [f"Suspicious process: {proc}", f"Host: {host_id}", f"PID: {pid}"],
        "tags": {"scenario_type": "SuspiciousProcessOnHost"},
    }

    return alert, score, plan


def _gen_benign_noise(rng: random.Random) -> Tuple[Dict, Dict, Dict]:
    src_ip = _random_ip(rng, "192.168")
    alert = {
        "sourceSiem": "simulator",
        "alertId": uuid.uuid4().hex,
        "type": "BenignNoise",
        "ruleName": "BenignNoise",
        "severity": rng.randint(5, 20),
        "entities": {
            "srcIp": src_ip,
            "hostname": None,
            "hostId": None,
            "username": None,
            "processName": None,
            "fileHash": None,
        },
    }
    alert["rawPayload"] = {"src_ip": src_ip, "attempts": rng.randint(1, 3)}

    score = {
        "severity": rng.randint(5, 20),
        "confidence": round(rng.uniform(0.15, 0.40), 2),
        "hypothesis": "Likely benign network noise or false positive.",
        "evidence": [f"src_ip={src_ip}", "low attempt count", "no malicious indicators"],
    }

    plan = {
        "planId": f"benign_{uuid.uuid4().hex[:8]}",
        "strategy": "NotifyOnly",
        "priority": rng.randint(5, 20),
        "summary": "Low-confidence alert, log and monitor only.",
        "actions": [
            {
                "type": "OpenTicket",
                "risk": 5,
                "expectedImpact": 5,
                "reversible": False,
                "parameters": {},
                "rationale": "Log the alert for record-keeping.",
            },
        ],
        "rollbackActions": [],
        "rationale": ["Low severity alert", "Likely benign noise", "No action required"],
        "tags": {"scenario_type": "BenignNoise"},
    }

    return alert, score, plan


def _gen_edge_missing_params(rng: random.Random) -> Tuple[Dict, Dict, Dict]:
    host_id = f"host-{rng.randint(100, 999)}"
    alert = {
        "sourceSiem": "simulator",
        "alertId": uuid.uuid4().hex,
        "type": "EdgeMissingParams",
        "ruleName": "EdgeMissingParams",
        "severity": rng.randint(30, 55),
        "entities": {
            "srcIp": None,
            "hostname": None,
            "hostId": host_id,
            "username": None,
            "processName": None,
            "fileHash": None,
        },
    }
    alert["rawPayload"] = {"host_id": host_id}

    score = {
        "severity": rng.randint(30, 55),
        "confidence": round(rng.uniform(0.40, 0.60), 2),
        "hypothesis": "Incomplete alert data, limited entity information available.",
        "evidence": [f"host_id={host_id}", "missing IP/user entities", "partial data only"],
    }

    # Low confidence — only safe actions
    plan = {
        "planId": f"edgeMissing_{uuid.uuid4().hex[:8]}",
        "strategy": "ObserveMore",
        "priority": rng.randint(20, 40),
        "summary": "Insufficient data for active response, log and monitor.",
        "actions": [
            {
                "type": "OpenTicket",
                "risk": 5,
                "expectedImpact": 5,
                "reversible": False,
                "parameters": {},
                "rationale": "Document partial alert for analyst review.",
            },
            {
                "type": "Notify",
                "risk": 5,
                "expectedImpact": 10,
                "reversible": False,
                "parameters": {},
                "rationale": "Notify SOC about incomplete alert requiring manual review.",
            },
        ],
        "rollbackActions": [],
        "rationale": ["Incomplete entity data", "Cannot determine full threat scope", "Manual review recommended"],
        "tags": {"scenario_type": "EdgeMissingParams"},
    }

    return alert, score, plan


# ---------------------------------------------------------------------------
# Prompt builders (must match production prompts exactly)
# ---------------------------------------------------------------------------

def build_scorer_prompt(alert: Dict[str, Any]) -> str:
    """Same format as intelligence/scorers/local_model.py::_build_scorer_prompt"""
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
    """Same format as intelligence/planners/local_model.py::_build_planner_prompt"""
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
        "- BlockIp: requires {\"src_ip\": \"<ip_address>\"}\n"
        "- UnblockIp: requires {\"src_ip\": \"<ip_address>\"}\n"
        "- IsolateHost: requires {\"host_id\": \"<id>\"} (optionally \"hostname\")\n"
        "- UnisolateHost: requires {\"host_id\": \"<id>\"} (optionally \"hostname\")\n"
        "- DisableUser: requires {\"username\": \"<name>\"} (optionally \"user_id\")\n"
        "- EnableUser: requires {\"username\": \"<name>\"} (optionally \"user_id\")\n"
        "- KillProcess: requires {\"host_id\": \"<id>\", \"process_name\": \"<name>\"}\n"
        "- QuarantineFile: requires {\"host_id\": \"<id>\", \"file_hash\": \"<hash>\"}\n"
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
        "2. Use the EXACT parameter key names listed above (e.g. \"src_ip\" not \"source_ip\").\n"
        "3. Copy entity values directly from the alert data - do not invent values.\n"
        "4. Always include at least an OpenTicket or Notify action for documentation.\n"
        "5. Keep the plan concise: 1-4 actions maximum.\n"
        f"{confidence_rule}\n"
        f"Available entity data from alert: {json.dumps(available) if available else 'NONE - only use OpenTicket/Notify'}\n\n"
        f"Alert:\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n\n"
        f"Assessment:\n{json.dumps(assessment, ensure_ascii=False, indent=2)}\n"
    )


# ---------------------------------------------------------------------------
# Variation helpers — add noise to make training data diverse
# ---------------------------------------------------------------------------

_HYPOTHESIS_VARIANTS = {
    "PortScanFromIp": [
        "Network reconnaissance via port scanning detected from a single source IP.",
        "Sequential port probing observed, indicative of network mapping activity.",
        "Automated port scan targeting multiple services on the network.",
        "Potential attacker performing service enumeration via TCP port scanning.",
    ],
    "BruteForceUser": [
        "Brute-force login attempt targeting a specific user account.",
        "Credential stuffing or password spraying attack detected.",
        "Multiple failed authentication attempts from a single source.",
        "Automated brute-force attack against user credentials.",
    ],
    "MalwareHashOnHost": [
        "Known malware hash detected on endpoint.",
        "File matching known malware signature found on host.",
        "Malicious binary identified by hash match on endpoint.",
        "Threat intelligence match: known malware detected on system.",
    ],
    "SuspiciousProcessOnHost": [
        "Suspicious process execution detected on endpoint.",
        "Potentially malicious process launched on host.",
        "Living-off-the-land binary execution flagged on endpoint.",
        "Unusual process activity detected, possible malware execution.",
    ],
    "BenignNoise": [
        "Likely benign network noise or false positive.",
        "Low-severity event, likely routine network activity.",
        "No malicious indicators found, probable false positive.",
        "Background noise alert, no immediate threat detected.",
    ],
    "EdgeMissingParams": [
        "Incomplete alert data, limited entity information available.",
        "Partial alert with insufficient data for confident assessment.",
        "Alert lacks key entity data for definitive threat classification.",
        "Insufficient context for reliable threat scoring.",
    ],
}

GENERATORS = [
    ("PortScanFromIp", _gen_port_scan, 0.20),
    ("BruteForceUser", _gen_brute_force, 0.20),
    ("MalwareHashOnHost", _gen_malware_hash, 0.18),
    ("SuspiciousProcessOnHost", _gen_suspicious_process, 0.17),
    ("BenignNoise", _gen_benign_noise, 0.15),
    ("EdgeMissingParams", _gen_edge_missing_params, 0.10),
]


def _add_variation(score: Dict, scenario: str, rng: random.Random) -> Dict:
    """Add hypothesis variation to avoid overfitting to single phrasings."""
    variants = _HYPOTHESIS_VARIANTS.get(scenario, [])
    if variants:
        score = dict(score)
        score["hypothesis"] = rng.choice(variants)
    return score


# ---------------------------------------------------------------------------
# Main generation
# ---------------------------------------------------------------------------

def generate(scorer_count: int, planner_count: int, seed: int = 42) -> Tuple[List[Dict], List[Dict]]:
    rng = random.Random(seed)
    scenarios = [name for name, _, _ in GENERATORS]
    weights = [w for _, _, w in GENERATORS]
    gen_map = {name: fn for name, fn, _ in GENERATORS}

    scorer_data: List[Dict] = []
    planner_data: List[Dict] = []

    for _ in range(max(scorer_count, planner_count)):
        scenario = rng.choices(scenarios, weights=weights, k=1)[0]
        alert, score, plan = gen_map[scenario](rng)
        score = _add_variation(score, scenario, rng)

        if len(scorer_data) < scorer_count:
            prompt = build_scorer_prompt(alert)
            completion = json.dumps(score, ensure_ascii=False)
            scorer_data.append({"prompt": prompt, "completion": completion})

        if len(planner_data) < planner_count:
            prompt = build_planner_prompt(alert, score)
            completion = json.dumps(plan, ensure_ascii=False)
            planner_data.append({"prompt": prompt, "completion": completion})

    return scorer_data, planner_data


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SOAR training data.")
    parser.add_argument("--output-dir", type=Path, default=Path("intelligence/training/data"))
    parser.add_argument("--scorer-count", type=int, default=600)
    parser.add_argument("--planner-count", type=int, default=600)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    scorer_data, planner_data = generate(args.scorer_count, args.planner_count, args.seed)

    scorer_path = args.output_dir / "scorer_train.jsonl"
    planner_path = args.output_dir / "planner_train.jsonl"

    with open(scorer_path, "w", encoding="utf-8") as f:
        for item in scorer_data:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    with open(planner_path, "w", encoding="utf-8") as f:
        for item in planner_data:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    print(f"Scorer examples: {len(scorer_data)} -> {scorer_path}")
    print(f"Planner examples: {len(planner_data)} -> {planner_path}")


if __name__ == "__main__":
    main()
