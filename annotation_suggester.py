import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List


HEURISTICS = [
    {
        "name": "noise_auth_success",
        "match_fields": ["rule"],
        "keywords": ["authentication success", "Windows logon success"],
        "detection_goal": "Treat this Windows authentication success as routine noise before raising the alert again.",
        "severity": "noise",
        "example_completion": "<group name=\"noise\"><rule id=\"100000\" level=\"1\"><description>Routine authentication success</description></rule></group>",
    },
    {
        "name": "powershell_usage",
        "match_fields": ["rule", "full_log"],
        "keywords": ["powershell", ".ps1", ".psm1"],
        "detection_goal": "Flag PowerShell activity, since PowerShell usage often indicates script-based abuse in your environment.",
        "severity": "high",
        "example_completion": "<group name=\"custom_sysmon_rules,process_injection\"><rule id=\"100650\" level=\"12\"><description>Suspicious PowerShell invocation</description></rule></group>",
    },
    {
        "name": "ssl_usage",
        "match_fields": ["rule", "full_log"],
        "keywords": ["ssl", "tls", "https://", "443"],
        "detection_goal": "Investigate SSL/TLS usage that might be hiding command-and-control or data exfiltration.",
        "severity": "medium",
        "example_completion": "<group name=\"custom_windows_rules,network\"><rule id=\"100651\" level=\"10\"><description>Unusual SSL/TLS traffic</description></rule></group>",
    },
    {
      "name": "root_execution",
      "match_fields": ["full_log"],
      "keywords": ["user=root", "sudo", "run as root"],
        "detection_goal": "High alert when root executes a program—track what commands are being issued as root.",
        "severity": "critical",
      "example_completion": "<group name=\"custom_unix_rules,root\"><rule id=\"100652\" level=\"13\"><description>Program execution as root</description></rule></group>",
    },
    {
      "name": "remote_access",
      "match_fields": ["rule", "full_log"],
      "keywords": ["remote shell", "remote access", "sshd", "rdesktop", "mstsc", "winrm", "remote desktop"],
      "detection_goal": "Treat remote access sessions as high risk until verified, especially when they appear without prior authorization.",
      "severity": "high",
      "example_completion": "<group name=\"local,remote_access\"><rule id=\"100660\" level=\"13\"><description>Unusual remote access activity</description></rule></group>",
    },
    {
      "name": "copy_sensitive",
        "match_fields": ["full_log"],
        "keywords": ["/etc/passwd", "/etc/shadow", "/etc/group"],
        "detection_goal": "Copying sensitive files (passwd/shadow/group) should raise a high alert even if the copy command looks normal.",
        "severity": "high",
        "example_completion": "<group name=\"custom_unix_rules,syscheck\"><rule id=\"100653\" level=\"13\"><description>Copy of sensitive credential files</description></rule></group>",
    },
    {
        "name": "unsigned_install",
        "match_fields": ["rule", "full_log"],
        "keywords": ["installation completed", "installed product"],
        "exclude_keywords": ["signed", "Microsoft", "verified"],
        "detection_goal": "Treat installs without a signature or vendor stamp as high risk.",
        "severity": "high",
        "example_completion": "<group name=\"local,software_install\"><rule id=\"100654\" level=\"12\"><description>Unsigned installer executed</description></rule></group>",
    },
    {
        "name": "signed_install",
        "match_fields": ["rule", "full_log"],
        "keywords": ["signed by", "verified", "digital signature"],
        "detection_goal": "Signed installs are mid/low priority but worth auditing for unexpected binaries.",
        "severity": "medium",
        "example_completion": "<group name=\"local,software_install\"><rule id=\"100655\" level=\"8\"><description>Signed installer seen</description></rule></group>",
    },
    {
        "name": "self_signed",
        "match_fields": ["rule", "full_log"],
        "keywords": ["self-signed", "self signed"],
        "detection_goal": "Self-signed binaries/certificates are suspicious; track the origin.",
        "severity": "high",
        "example_completion": "<group name=\"local,software_install\"><rule id=\"100656\" level=\"12\"><description>Self-signed binary detected</description></rule></group>",
    },
    {
        "name": "login_geo_anomaly",
        "matcher": "login_geo_matcher",
        "detection_goal": "Raise a very high alert when the same account authenticates from differing IPs within a short period.",
        "severity": "critical",
        "example_completion": "<group name=\"custom_windows_rules,authentication\"><rule id=\"100657\" level=\"14\"><description>Account used from multiple locations quickly</description></rule></group>",
    },
    {
        "name": "privilege_escalation",
        "match_fields": ["rule", "full_log"],
        "keywords": ["privilege escalation", "Privilege Escalation"],
        "detection_goal": "Confirm whether this privilege escalation alert is real or just noise from scripted activity.",
        "severity": "high",
        "example_completion": "<group name=\"local,sudo\"><rule id=\"100658\" level=\"13\"><description>Privilege escalation activity</description></rule></group>",
    },
    {
        "name": "rootcheck_trojan",
        "match_fields": ["rule", "full_log"],
        "keywords": ["rootcheck", "trojaned version"],
        "detection_goal": "Treat Trojaned system utilities flagged by rootcheck as high-risk detections.",
        "severity": "high",
        "example_completion": "<group name=\"custom_rules,rootcheck\"><rule id=\"100659\" level=\"12\"><description>Rootcheck reported trojaned binary</description></rule></group>",
    },
]


def parse_json_field(value: str) -> Dict[str, Any]:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}


def text_contains_any(text: str, keywords: List[str]) -> bool:
    lowered = text.lower()
    return any(keyword.lower() in lowered for keyword in keywords)


def text_contains_all(text: str, keywords: List[str]) -> bool:
    lowered = text.lower()
    return all(keyword.lower() in lowered for keyword in keywords)


def login_geo_matcher(
    row: Dict[str, str],
    rule: Dict[str, Any],
    log_text: str,
    context: Dict[str, Any],
) -> bool:
    agent_data = parse_json_field(row.get("agent", ""))
    agent_id = agent_data.get("id") or agent_data.get("name")
    ip = agent_data.get("ip")
    if not agent_id or not ip:
        return False
    history = context.setdefault("login_history", {})
    previous_ip = history.get(agent_id)
    if previous_ip and previous_ip != ip:
        history[agent_id] = ip
        return True
    history[agent_id] = ip
    return False


def match_heuristic(
    row: Dict[str, str],
    rule: Dict[str, Any],
    heur: Dict[str, Any],
    context: Dict[str, Any],
) -> bool:
    log_text = row.get("full_log", "") or ""
    rule_text = row.get("rule", "") or ""
    description = rule.get("description", "") if rule else ""
    if heur.get("matcher"):
        matcher_name = heur["matcher"]
        if matcher_name == "login_geo_matcher":
            return login_geo_matcher(row, rule, log_text, context)
        return False

    for field in heur.get("match_fields", []):
        field_text = ""
        if field == "rule":
            field_text = rule_text
        elif field == "description":
            field_text = description
        elif field == "full_log":
            field_text = log_text
        else:
            field_text = row.get(field, "") or ""

        field_text = field_text.lower()
        if heur.get("exclude_keywords") and text_contains_any(field_text, heur["exclude_keywords"]):
            continue

        if heur.get("all_keywords") and not text_contains_all(field_text, heur["all_keywords"]):
            continue
        if heur.get("keywords") and text_contains_any(field_text, heur["keywords"]):
            return True

    return False


def build_candidate(
    row: Dict[str, str],
    heur: Dict[str, Any],
    rule: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "dataset_id": row.get("id"),
        "timestamp": row.get("timestamp"),
        "heuristic": heur["name"],
        "severity": heur.get("severity", "info"),
        "detection_goal": heur.get("detection_goal"),
        "rule_description": rule.get("description", "") if rule else "",
        "log_excerpt": (row.get("full_log") or "")[:200],
        "example_completion": heur.get("example_completion"),
    }


def scan_logs(
    dataset_path: Path,
    limit_per_heuristic: int,
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    counts: Dict[str, int] = defaultdict(int)
    context: Dict[str, Any] = {}
    with dataset_path.open("r", encoding="utf-8", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            rule = parse_json_field(row.get("rule", ""))
            for heur in HEURISTICS:
                name = heur["name"]
                if limit_per_heuristic > 0 and counts[name] >= limit_per_heuristic:
                    continue
                if match_heuristic(row, rule, heur, context):
                    candidates.append(build_candidate(row, heur, rule))
                    counts[name] += 1
    return candidates


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate annotation candidates from dataset logs using heuristic rules."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("data/dataset.csv"),
        help="Path to the CSV dataset.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("training_candidates.json"),
        help="Where to write the candidate annotations.",
    )
    parser.add_argument(
        "--limit-per-heuristic",
        type=int,
        default=20,
        help="Max number of candidates to emit for each heuristic (default: 20).",
    )

    args = parser.parse_args()
    candidates = scan_logs(args.dataset, args.limit_per_heuristic)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as out_file:
        json.dump(candidates, out_file, ensure_ascii=False, indent=2)

    summary = defaultdict(int)
    for candidate in candidates:
        summary[candidate["heuristic"]] += 1

    print(f"Generated {len(candidates)} candidate annotations.")
    for heur_name, count in summary.items():
        print(f"  {heur_name}: {count}")
    print(f"Saved candidates to {args.output}")


if __name__ == "__main__":
    main()
