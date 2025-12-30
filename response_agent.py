import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Sequence

from annotation_suggester import HEURISTICS, match_heuristic, parse_json_field


DEFAULT_RESPONSE_ACTIONS: Dict[str, Sequence[str]] = {
    "critical": [
        "Isolate the affected host from the network (disable interfaces or remove from VPN).",
        "Notify SOC immediately and document the detection details.",
        "Capture volatile memory/log snapshots before the host is rebooted.",
    ],
    "high": [
        "Block the source IP at the firewall or host-based firewall.",
        "Stage the host for forensic triage (collect disk image, eventlogs).",
        "Up the logging verbosity and monitor for follow-on activity.",
    ],
    "medium": [
        "Correlate with other detections to confirm impact.",
        "Notify the owner/team and continue to monitor the host.",
    ],
    "low": [
        "Log the event for record keeping and review during the next shift.",
        "Confirm whether the behavior is expected before escalating.",
    ],
    "noise": [
        "Mark the detection as noise to reduce future alert volume.",
        "Tune the matching rule instead of escalating the incident.",
    ],
    "default": [
        "Document the detection and hand off to the analyst queue for investigation.",
    ],
}


class ResponseAgent:
    def __init__(
        self,
        dataset_path: Path,
        limit_per_heuristic: int,
        response_actions: Dict[str, Sequence[str]],
    ) -> None:
        self.dataset_path = dataset_path
        self.limit_per_heuristic = limit_per_heuristic
        self.response_actions = {
            key.lower(): list(values) for key, values in response_actions.items()
        }
        if "default" not in self.response_actions:
            self.response_actions["default"] = []

    def generate_actions(self) -> List[Dict[str, Any]]:
        plans: List[Dict[str, Any]] = []
        counts: Dict[str, int] = defaultdict(int)
        context: Dict[str, Any] = {}
        with self.dataset_path.open("r", encoding="utf-8", newline="") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                rule = parse_json_field(row.get("rule", ""))
                for heur in HEURISTICS:
                    name = heur["name"]
                    if self.limit_per_heuristic > 0 and counts[name] >= self.limit_per_heuristic:
                        continue
                    if not match_heuristic(row, rule, heur, context):
                        continue

                    plans.append(self._build_plan(row, rule, heur))
                    counts[name] += 1
        return plans

    def _build_plan(
        self,
        row: Dict[str, str],
        rule: Dict[str, Any],
        heur: Dict[str, Any],
    ) -> Dict[str, Any]:
        agent_info = self._parse_agent(row.get("agent", ""))
        severity = heur.get("severity", "default")
        return {
            "dataset_id": row.get("id"),
            "timestamp": row.get("timestamp"),
            "host": agent_info.get("name") or agent_info.get("id") or row.get("agent"),
            "ip": agent_info.get("ip"),
            "rule_id": rule.get("id"),
            "rule_description": rule.get("description"),
            "log_excerpt": (row.get("full_log") or "")[:400],
            "heuristic": heur["name"],
            "detection_goal": heur.get("detection_goal"),
            "severity": severity,
            "actions": self._select_actions(severity),
        }

    def _select_actions(self, severity: str) -> List[str]:
        severity_key = severity.lower()
        return self.response_actions.get(
            severity_key, self.response_actions.get("default", [])
        )

    @staticmethod
    def _parse_agent(agent_field: str) -> Dict[str, Any]:
        parsed = parse_json_field(agent_field)
        if parsed:
            return parsed
        return {"name": agent_field}


def load_action_map(path: Path | None) -> Dict[str, Sequence[str]]:
    if not path:
        return DEFAULT_RESPONSE_ACTIONS
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Action map must be a JSON object.")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate response action plans for detected attack heuristics."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("data/dataset.csv"),
        help="Path to the CSV dataset containing parsed Wazuh events.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to a JSON file where the action plans will be written.",
    )
    parser.add_argument(
        "--limit-per-heuristic",
        type=int,
        default=0,
        help="Maximum number of plans to emit per heuristic (0 means no limit).",
    )
    parser.add_argument(
        "--actions",
        type=Path,
        help="Optional JSON file that maps severity levels to action lists.",
    )

    args = parser.parse_args()
    action_map = load_action_map(args.actions)
    agent = ResponseAgent(
        dataset_path=args.dataset,
        limit_per_heuristic=args.limit_per_heuristic,
        response_actions=action_map,
    )
    plans = agent.generate_actions()

    print(f"Detected {len(plans)} actionable events.")
    for plan in plans:
        print(
            f"- {plan['heuristic']} ({plan['severity']}) on {plan['host']}: "
            f"{len(plan['actions'])} suggested action(s)"
        )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(plans, indent=2, ensure_ascii=False))
        print(f"Saved plans to {args.output}")


if __name__ == "__main__":
    main()
