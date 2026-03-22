"""
Baseline test: sends diverse alerts to the intelligence service and records
scorer + planner responses for before/after fine-tuning comparison.
"""
import json
import time
import subprocess
import sys
import requests

BASE = "http://127.0.0.1:8080"

TEST_ALERTS = [
    {
        "alertId": "baseline-001",
        "alertType": "PortScanFromIp",
        "severity": 5,
        "ruleName": "PortScanFromIp",
        "rawLog": "Multiple connection attempts from 10.0.5.22 to ports 22,80,443,8080,3389",
        "entities": {
            "src_ip": "10.0.5.22",
            "hostname": None,
            "host_id": None,
            "username": None,
            "user_id": None,
            "file_hash": None,
            "process_name": None,
        },
    },
    {
        "alertId": "baseline-002",
        "alertType": "BruteForceUser",
        "severity": 7,
        "ruleName": "BruteForceUser",
        "rawLog": "45 failed login attempts for user admin from 172.16.10.5",
        "entities": {
            "src_ip": "172.16.10.5",
            "hostname": None,
            "host_id": None,
            "username": "admin",
            "user_id": "u-1001",
            "file_hash": None,
            "process_name": None,
        },
    },
    {
        "alertId": "baseline-003",
        "alertType": "MalwareHashOnHost",
        "severity": 9,
        "ruleName": "MalwareHashOnHost",
        "rawLog": "Known malware hash detected: abc123def456 on host-201 at C:\\temp\\evil.exe",
        "entities": {
            "src_ip": None,
            "hostname": "WORKSTATION-07",
            "host_id": "host-201",
            "username": None,
            "user_id": None,
            "file_hash": "abc123def456789abcdef0123456789a",
            "process_name": None,
        },
    },
    {
        "alertId": "baseline-004",
        "alertType": "SuspiciousProcessOnHost",
        "severity": 8,
        "ruleName": "SuspiciousProcessOnHost",
        "rawLog": "powershell.exe spawned encoded command on host-305",
        "entities": {
            "src_ip": None,
            "hostname": "SERVER-DB-01",
            "host_id": "host-305",
            "username": None,
            "user_id": None,
            "file_hash": None,
            "process_name": "powershell.exe",
        },
    },
    {
        "alertId": "baseline-005",
        "alertType": "BenignNoise",
        "severity": 1,
        "ruleName": "BenignNoise",
        "rawLog": "Routine DNS query from 192.168.1.50 to internal resolver",
        "entities": {
            "src_ip": "192.168.1.50",
            "hostname": None,
            "host_id": None,
            "username": None,
            "user_id": None,
            "file_hash": None,
            "process_name": None,
        },
    },
    {
        "alertId": "baseline-006",
        "alertType": "PortScanFromIp",
        "severity": 6,
        "ruleName": "PortScanFromIp",
        "rawLog": "SYN scan detected from 10.0.8.100 targeting 10.0.1.0/24 on ports 22,3389,445",
        "entities": {
            "src_ip": "10.0.8.100",
            "hostname": None,
            "host_id": None,
            "username": None,
            "user_id": None,
            "file_hash": None,
            "process_name": None,
        },
    },
]


def wait_for_service(timeout=30):
    for _ in range(timeout):
        try:
            r = requests.get(f"{BASE}/health", timeout=2)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def run_baseline():
    print("Waiting for intelligence service...")
    if not wait_for_service():
        print("ERROR: intelligence service not reachable at", BASE)
        sys.exit(1)
    print("Service is up.\n")

    results = []
    for alert in TEST_ALERTS:
        aid = alert["alertId"]
        atype = alert["alertType"]
        print(f"[{aid}] Scoring {atype}...")

        # Score
        try:
            r = requests.post(f"{BASE}/v1/score", json=alert, timeout=120)
            score_resp = r.json() if r.status_code == 200 else {"error": r.text}
        except Exception as e:
            score_resp = {"error": str(e)}

        print(f"  Scorer: severity={score_resp.get('severity','?')} confidence={score_resp.get('confidence','?')}")

        # Plan
        assessment = score_resp if "error" not in score_resp else {
            "severity": 50, "confidence": 0.5, "hypothesis": "fallback", "evidence": []
        }
        try:
            r = requests.post(
                f"{BASE}/v1/plan",
                json={"alert": alert, "assessment": assessment},
                timeout=120,
            )
            plan_resp = r.json() if r.status_code == 200 else {"error": r.text}
        except Exception as e:
            plan_resp = {"error": str(e)}

        strategy = plan_resp.get("strategy", "?")
        actions = plan_resp.get("actions", [])
        action_types = [a.get("type", "?") for a in actions]
        print(f"  Planner: strategy={strategy} actions={action_types}")

        results.append({
            "alertId": aid,
            "alertType": atype,
            "scorer_response": score_resp,
            "planner_response": plan_resp,
        })
        print()

    return results


def summarize(results):
    lines = ["=" * 60, "BASELINE METRICS SUMMARY (baron-security)", "=" * 60, ""]

    total = len(results)
    scorer_ok = sum(1 for r in results if "error" not in r["scorer_response"])
    planner_ok = sum(1 for r in results if "error" not in r["planner_response"])

    lines.append(f"Total alerts tested: {total}")
    lines.append(f"Scorer success: {scorer_ok}/{total}")
    lines.append(f"Planner success: {planner_ok}/{total}")
    lines.append("")

    # Scorer metrics
    lines.append("--- Scorer Results ---")
    severities = []
    confidences = []
    for r in results:
        s = r["scorer_response"]
        if "error" not in s:
            sev = s.get("severity", "?")
            conf = s.get("confidence", "?")
            hyp = s.get("hypothesis", "?")
            severities.append(sev if isinstance(sev, (int, float)) else 0)
            confidences.append(conf if isinstance(conf, (int, float)) else 0)
            lines.append(f"  [{r['alertId']}] {r['alertType']}: severity={sev} confidence={conf}")
            lines.append(f"    hypothesis: {hyp}")
        else:
            lines.append(f"  [{r['alertId']}] {r['alertType']}: ERROR - {s['error'][:100]}")

    if severities:
        lines.append(f"\n  Avg severity: {sum(severities)/len(severities):.1f}")
        lines.append(f"  Avg confidence: {sum(confidences)/len(confidences):.3f}")

    # Planner metrics
    lines.append("\n--- Planner Results ---")
    strategies = {}
    all_action_types = {}
    for r in results:
        p = r["planner_response"]
        if "error" not in p:
            strat = p.get("strategy", "?")
            strategies[strat] = strategies.get(strat, 0) + 1
            actions = p.get("actions", [])
            atypes = [a.get("type", "?") for a in actions]
            lines.append(f"  [{r['alertId']}] {r['alertType']}: strategy={strat} actions={atypes}")
            for at in atypes:
                all_action_types[at] = all_action_types.get(at, 0) + 1
        else:
            lines.append(f"  [{r['alertId']}] {r['alertType']}: ERROR - {p['error'][:100]}")

    lines.append(f"\n  Strategy distribution: {dict(strategies)}")
    lines.append(f"  Action type distribution: {dict(all_action_types)}")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    results = run_baseline()
    summary = summarize(results)
    print(summary)

    outpath = "intelligence/training/data/baseline_metrics.json"
    with open(outpath, "w") as f:
        json.dump(
            {
                "model": "baron-security (ollama)",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "test_alerts": TEST_ALERTS,
                "results": results,
                "summary_text": summary,
            },
            f,
            indent=2,
        )
    print(f"\nBaseline saved to {outpath}")
