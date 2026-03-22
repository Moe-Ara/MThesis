"""
replay_alerts.py — Replay real SIEM alerts through the SOAR engine webhook.

Usage:
    python scripts/replay_alerts.py [--siem wazuh|sentinel|all] [--limit N] [--delay SEC]

Examples:
    # Replay top 10 interesting Wazuh alerts
    python scripts/replay_alerts.py --siem wazuh --limit 10

    # Replay synthetic Sentinel alerts
    python scripts/replay_alerts.py --siem sentinel

    # Replay both sequentially
    python scripts/replay_alerts.py --siem all --delay 1.5

Requires ORCHESTRATOR_WEBHOOK_URL to be set in .env or environment.
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

ALERTS_FILE = Path(__file__).parent.parent / "data" / "alerts.json"
WEBHOOK_URL_DEFAULT = "http://localhost:5050/"

# High-severity Wazuh rule groups worth showing in a demo
INTERESTING_GROUPS = {
    "ransomware", "authentication_failed", "intrusion_detection",
    "sysmon_process-anomalies", "sysmon_eid13_detections", "web",
    "exploit", "rootcheck", "sudo",
}

# Minimum rule level (Wazuh 0-15 scale) to include
MIN_RULE_LEVEL = 7

# ── Synthetic Sentinel alerts ─────────────────────────────────────────────────

# Realistic Wazuh-format alerts with full entity context (production-style).
# The archived dataset lacks rich entity fields; these represent alerts from a production Wazuh deployment.
WAZUH_RICH_ALERTS = [
    {
        "timestamp": "2026-03-07T08:14:22.000+0000",
        "rule": {
            "level": 10, "id": "5763",
            "description": "sshd: Multiple failed authentication attempts (possible brute-force).",
            "groups": ["syslog", "sshd", "authentication_failed", "brute_force"],
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}
        },
        "agent": {"id": "001", "name": "web-server-prod"},
        "id": "demo-brute-001",
        "data": {"srcip": "185.220.101.47", "srcuser": "root", "failed_logins": 87,
                 "dstport": "22", "program_name": "sshd"}
    },
    {
        "timestamp": "2026-03-07T09:02:11.000+0000",
        "rule": {
            "level": 14, "id": "100505",
            "description": "Known malware hash detected on endpoint - Trojan.GenericKD.",
            "groups": ["malware", "sysmon", "windows", "custom_rules"],
            "mitre": {"id": ["T1204.002"], "tactic": ["Execution"], "technique": ["Malicious File"]}
        },
        "agent": {"id": "003", "name": "finance-laptop-07"},
        "id": "demo-malware-001",
        "data": {
            "srcip": "192.168.10.45",
            "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "file": "C:\\Users\\jdoe\\Downloads\\invoice.exe",
            "win": {"eventdata": {"image": "invoice.exe", "user": "jdoe"}}
        }
    },
    {
        "timestamp": "2026-03-07T10:45:03.000+0000",
        "rule": {
            "level": 12, "id": "92210",
            "description": "Sysmon: Suspicious PowerShell launched with encoded command from Word.",
            "groups": ["sysmon", "sysmon_process-anomalies", "windows", "custom_rules"],
            "mitre": {"id": ["T1059.001", "T1027"], "tactic": ["Execution", "Defense Evasion"],
                      "technique": ["PowerShell", "Obfuscated Files"]}
        },
        "agent": {"id": "005", "name": "hr-workstation-12"},
        "id": "demo-proc-001",
        "data": {
            "win": {
                "eventdata": {
                    "image": "powershell.exe",
                    "commandLine": "powershell.exe -EncodedCommand JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                    "parentImage": "WINWORD.EXE",
                    "user": "hsmith"
                }
            }
        }
    }
]

SENTINEL_ALERTS = [
    {
        "id": "/subscriptions/sub-001/resourceGroups/rg-soc/providers/Microsoft.SecurityInsights/incidents/201",
        "name": "201",
        "properties": {
            "title": "Suspicious PowerShell Execution - Encoded Command",
            "description": "A PowerShell process was launched with a base64-encoded command, a common technique used to bypass script-block logging.",
            "severity": "High",
            "status": "New",
            "createdTimeUtc": "2026-03-07T08:12:00Z",
            "incidentNumber": 201,
            "entities": [
                {
                    "kind": "Host",
                    "properties": {"hostName": "ws-finance-03", "omsAgentId": "host-203"}
                },
                {
                    "kind": "Account",
                    "properties": {"accountName": "hchen"}
                },
                {
                    "kind": "Process",
                    "properties": {"commandLine": "powershell.exe -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA="}
                }
            ],
            "additionalData": {
                "tactics": ["Execution", "Defense Evasion"],
                "techniques": ["T1059.001", "T1027"]
            }
        }
    },
    {
        "id": "/subscriptions/sub-001/resourceGroups/rg-soc/providers/Microsoft.SecurityInsights/incidents/202",
        "name": "202",
        "properties": {
            "title": "Brute Force Attack Against Azure AD — Multiple Failed Sign-Ins",
            "description": "More than 50 failed sign-in attempts were detected against the account from a single IP address within 10 minutes.",
            "severity": "High",
            "status": "New",
            "createdTimeUtc": "2026-03-07T09:34:00Z",
            "incidentNumber": 202,
            "entities": [
                {
                    "kind": "Ip",
                    "properties": {"address": "185.220.101.47"}
                },
                {
                    "kind": "Account",
                    "properties": {"accountName": "admin@contoso.com"}
                }
            ],
            "additionalData": {
                "tactics": ["Credential Access"],
                "techniques": ["T1110.001"]
            }
        }
    },
    {
        "id": "/subscriptions/sub-001/resourceGroups/rg-soc/providers/Microsoft.SecurityInsights/incidents/203",
        "name": "203",
        "properties": {
            "title": "Known Malware Hash Detected on Endpoint",
            "description": "A file matching a known malware hash was written to disk on a corporate endpoint.",
            "severity": "Critical",
            "status": "New",
            "createdTimeUtc": "2026-03-07T10:05:00Z",
            "incidentNumber": 203,
            "entities": [
                {
                    "kind": "Host",
                    "properties": {"hostName": "laptop-exec-07", "omsAgentId": "host-507"}
                },
                {
                    "kind": "FileHash",
                    "properties": {"hashValue": "d41d8cd98f00b204e9800998ecf8427e", "algorithm": "MD5"}
                }
            ],
            "additionalData": {
                "tactics": ["Execution"],
                "techniques": ["T1204.002"]
            }
        }
    }
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def load_env(path: Path = Path(".env")) -> dict:
    env = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        env[key.strip()] = val.strip().strip('"').strip("'")
    return env


def post_alert(webhook_url: str, payload: dict, siem_name: str) -> bool:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Siem-Name": siem_name,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            ok = 200 <= status < 300
            if not ok:
                print(f"  [WARN] HTTP {status}", file=sys.stderr)
            return ok
    except urllib.error.HTTPError as e:
        print(f"  [ERROR] HTTP {e.code}: {e.reason}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"  [ERROR] {e}", file=sys.stderr)
        return False


def load_wazuh_alerts() -> list:
    if not ALERTS_FILE.exists():
        print(f"[WARN] {ALERTS_FILE} not found — skipping Wazuh alerts", file=sys.stderr)
        return []

    alerts = []
    with ALERTS_FILE.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return alerts


def filter_wazuh_alerts(alerts: list, limit: int) -> list:
    """Select the most interesting alerts for the demo."""
    scored = []
    for a in alerts:
        rule = a.get("rule", {})
        level = rule.get("level", 0)
        groups = set(rule.get("groups", []))
        data = a.get("data", {})

        if level < MIN_RULE_LEVEL:
            continue

        # Prefer alerts with interesting groups
        group_score = len(groups & INTERESTING_GROUPS)
        # Prefer alerts with actual data fields
        data_score = len([v for v in data.values() if v and v != data.get("title", "")])

        scored.append((group_score * 10 + level + data_score, a))

    scored.sort(key=lambda x: x[0], reverse=True)

    # Deduplicate by rule ID (keep highest-scored per rule)
    seen_rules = set()
    selected = []
    for _, a in scored:
        rule_id = a.get("rule", {}).get("id", "")
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            selected.append(a)
        if len(selected) >= limit:
            break

    return selected


def describe_wazuh(a: dict) -> str:
    rule = a.get("rule", {})
    return (f"[Wazuh] rule={rule.get('id','')} level={rule.get('level',0)} "
            f"— {rule.get('description','')[:70]}")


def describe_sentinel(a: dict) -> str:
    props = a.get("properties", a)
    return (f"[Sentinel] incident #{props.get('incidentNumber','')} "
            f"severity={props.get('severity','')} "
            f"— {props.get('title','')[:60]}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Replay SIEM alerts to SOAR engine webhook")
    parser.add_argument("--siem", choices=["wazuh", "sentinel", "all", "wazuh-rich", "demo"], default="all",
                        help="Which SIEM source to replay (default: all). "
                             "'demo' sends only production-quality alerts (3 Wazuh-rich + 3 Sentinel = 6 alerts). "
                             "'wazuh-rich' sends the 3 production-style Wazuh alerts. "
                             "'all' sends wazuh-rich + archived Wazuh + Sentinel.")
    parser.add_argument("--limit", type=int, default=8,
                        help="Max number of Wazuh alerts to replay (default: 8)")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Delay in seconds between alerts (default: 1.0)")
    parser.add_argument("--webhook", type=str, default=None,
                        help="Override webhook URL")
    args = parser.parse_args()

    # Resolve webhook URL
    env = load_env(Path(__file__).parent.parent / ".env")
    webhook_url = args.webhook or env.get("ORCHESTRATOR_WEBHOOK_URL") or WEBHOOK_URL_DEFAULT
    webhook_url = webhook_url.rstrip("/") + "/"

    print(f"Webhook target: {webhook_url}")
    print(f"SIEM mode: {args.siem} | delay: {args.delay}s")
    print("-" * 60)

    sent = 0
    failed = 0

    # ── Wazuh rich (production-style with full entities) ─────────
    if args.siem in ("wazuh-rich", "all", "demo"):
        print(f"\n>> Replaying {len(WAZUH_RICH_ALERTS)} production-style Wazuh alerts...")
        for i, alert in enumerate(WAZUH_RICH_ALERTS, 1):
            rule = alert.get("rule", {})
            desc = f"[Wazuh] rule={rule.get('id','')} level={rule.get('level','')} - {rule.get('description','')[:55]}"
            print(f"  [{i}/{len(WAZUH_RICH_ALERTS)}] {desc}")
            ok = post_alert(webhook_url, alert, siem_name="wazuh")
            if ok:
                sent += 1
                print(f"         OK accepted")
            else:
                failed += 1
            if i < len(WAZUH_RICH_ALERTS):
                time.sleep(args.delay)

    # ── Wazuh alerts ──────────────────────────────────────────────
    if args.siem in ("wazuh", "all"):
        raw_alerts = load_wazuh_alerts()
        selected = filter_wazuh_alerts(raw_alerts, limit=args.limit)
        print(f"\n>> Replaying {len(selected)} Wazuh alerts from {ALERTS_FILE.name}...")

        for i, alert in enumerate(selected, 1):
            desc = describe_wazuh(alert)
            print(f"  [{i}/{len(selected)}] {desc}")
            ok = post_alert(webhook_url, alert, siem_name="wazuh")
            if ok:
                sent += 1
                print(f"         OK accepted")
            else:
                failed += 1
            if i < len(selected):
                time.sleep(args.delay)

    # Sentinel alerts
    if args.siem in ("sentinel", "all", "demo"):
        if args.siem == "all":
            time.sleep(args.delay)
        print(f"\n>> Replaying {len(SENTINEL_ALERTS)} Microsoft Sentinel alerts...")

        for i, alert in enumerate(SENTINEL_ALERTS, 1):
            desc = describe_sentinel(alert)
            print(f"  [{i}/{len(SENTINEL_ALERTS)}] {desc}")
            ok = post_alert(webhook_url, alert, siem_name="sentinel")
            if ok:
                sent += 1
                print(f"         OK accepted")
            else:
                failed += 1
            if i < len(SENTINEL_ALERTS):
                time.sleep(args.delay)

    print(f"\n{'='*60}")
    print(f"Done. Sent: {sent}  Failed: {failed}")


if __name__ == "__main__":
    main()
