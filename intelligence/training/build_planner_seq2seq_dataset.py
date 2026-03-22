import argparse
import json
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from intelligence.core.utils import extract_json, repair_json
from intelligence.planners.prompting import build_planner_prompt_compact, build_planner_prompt_minimal, build_planner_prompt_seq2seq
from intelligence.planners.plan_utils import sanitize_plan

ALLOWED_PARAMS = {
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

REQUIRED_PARAMS = {
    "BlockIp": {"src_ip"},
    "UnblockIp": {"src_ip"},
    "IsolateHost": {"host_id"},
    "UnisolateHost": {"host_id"},
    "DisableUser": {"username"},
    "EnableUser": {"username"},
    "KillProcess": {"host_id", "process_name"},
    "QuarantineFile": {"host_id", "file_hash"},
}

PARAM_ALIASES = {
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


def _extract_json_object(text: str, start_index: int) -> Optional[Dict[str, Any]]:
    start = text.find("{", start_index)
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                snippet = text[start : i + 1]
                try:
                    return json.loads(snippet)
                except json.JSONDecodeError:
                    return extract_json(snippet) or repair_json(snippet)
    return None


def _parse_prompt(prompt: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    alert = None
    assessment = None

    alert_idx = prompt.rfind("AlertSummary:")
    if alert_idx == -1:
        alert_idx = prompt.rfind("Alert:")
    if alert_idx != -1:
        alert = _extract_json_object(prompt, alert_idx)

    assess_idx = prompt.rfind("AssessmentSummary:")
    if assess_idx == -1:
        assess_idx = prompt.rfind("Assessment:")
    if assess_idx != -1:
        assessment = _extract_json_object(prompt, assess_idx)

    return alert, assessment


def _parse_completion(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return extract_json(raw) or repair_json(raw)


def _canonicalize_params(action_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
    allowed = ALLOWED_PARAMS.get(action_type)
    if allowed is None:
        return {}
    if not allowed:
        return {}

    cleaned: Dict[str, Any] = {}
    for key, value in params.items():
        if key in allowed:
            cleaned[key] = value
            continue
        alias = PARAM_ALIASES.get(key)
        if alias and alias in allowed and alias not in cleaned:
            cleaned[alias] = value
    return cleaned


def _has_required_params(action_type: str, params: Dict[str, Any]) -> bool:
    required = REQUIRED_PARAMS.get(action_type)
    if not required:
        return True
    return all(k in params and params[k] not in (None, "") for k in required)


def _canonicalize_actions(actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cleaned_actions: List[Dict[str, Any]] = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        action_type = action.get("type")
        if not action_type or action_type not in ALLOWED_PARAMS:
            continue
        params = action.get("parameters") or {}
        if not isinstance(params, dict):
            params = {}
        params = _canonicalize_params(action_type, params)
        if not _has_required_params(action_type, params):
            continue
        action["parameters"] = params
        cleaned_actions.append(action)
    return cleaned_actions


def _slim_completion(plan: Dict[str, Any]) -> str:
    """Create a compact JSON completion that fits within ~256 T5 tokens.

    Strips verbose rationale strings and keeps only structural fields.
    """
    slim_actions = []
    for a in plan.get("actions", []):
        slim_a = {"type": a.get("type", "")}
        params = a.get("parameters") or {}
        if params:
            slim_a["parameters"] = params
        slim_actions.append(slim_a)

    slim_rollback = []
    for r in plan.get("rollbackActions", []):
        slim_r = {"type": r.get("type", "")}
        params = r.get("parameters") or {}
        if params:
            slim_r["parameters"] = params
        slim_rollback.append(slim_r)

    slim = {
        "strategy": plan.get("strategy", ""),
        "priority": plan.get("priority", 50),
        "actions": slim_actions,
        "rollbackActions": slim_rollback,
    }
    return json.dumps(slim, ensure_ascii=False)


def _format_action_pipe(action: Dict[str, Any]) -> str:
    """Format a single action in pipe-friendly notation: Type(key=val,key=val)."""
    action_type = action.get("type", "")
    params = action.get("parameters") or {}
    if not params:
        return action_type
    param_str = ",".join(f"{k}={v}" for k, v in params.items())
    return f"{action_type}({param_str})"


def _pipe_completion(plan: Dict[str, Any]) -> str:
    """Create a pipe-delimited completion for T5 (no curly braces needed).

    T5's SentencePiece tokenizer maps { and } to <unk>, so JSON output
    is impossible. This format uses pipe delimiters instead:
      strategy=X|priority=N|actions=A(p=v),B|rollback=C(p=v)
    """
    strategy = plan.get("strategy", "")
    priority = plan.get("priority", 50)
    actions = [_format_action_pipe(a) for a in plan.get("actions", []) if isinstance(a, dict)]
    rollback = [_format_action_pipe(r) for r in plan.get("rollbackActions", []) if isinstance(r, dict)]
    parts = [
        f"strategy={strategy}",
        f"priority={priority}",
        f"actions={','.join(actions)}" if actions else "actions=",
    ]
    if rollback:
        parts.append(f"rollback={','.join(rollback)}")
    return "|".join(parts)


def parse_pipe_completion(text: str) -> Dict[str, Any]:
    """Parse a pipe-delimited completion back into a plan dict."""
    result: Dict[str, Any] = {"strategy": "", "priority": 50, "actions": [], "rollbackActions": []}
    for segment in text.split("|"):
        if "=" not in segment:
            continue
        key, _, value = segment.partition("=")
        key = key.strip()
        value = value.strip()
        if key == "strategy":
            result["strategy"] = value
        elif key == "priority":
            try:
                result["priority"] = int(value)
            except ValueError:
                pass
        elif key in ("actions", "rollback"):
            action_list = []
            if value:
                for action_str in _split_actions(value):
                    action_list.append(_parse_action_pipe(action_str))
            if key == "actions":
                result["actions"] = action_list
            else:
                result["rollbackActions"] = action_list
    return result


def _split_actions(text: str) -> List[str]:
    """Split comma-separated actions, respecting parentheses."""
    actions = []
    depth = 0
    current: List[str] = []
    for ch in text:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            actions.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        actions.append("".join(current).strip())
    return [a for a in actions if a]


def _parse_action_pipe(text: str) -> Dict[str, Any]:
    """Parse 'Type(key=val,key=val)' into action dict."""
    paren = text.find("(")
    if paren == -1:
        return {"type": text.strip()}
    action_type = text[:paren].strip()
    params_str = text[paren + 1 :].rstrip(")")
    params = {}
    for pair in params_str.split(","):
        if "=" in pair:
            k, _, v = pair.partition("=")
            params[k.strip()] = v.strip()
    action: Dict[str, Any] = {"type": action_type}
    if params:
        action["parameters"] = params
    return action


def _normalize_plan(plan: Dict[str, Any], alert: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
    normalized = sanitize_plan(plan, alert, assessment, derive_strategy_from_actions=True)
    cleaned_actions = []
    for action in normalized.get("actions", []):
        if not isinstance(action, dict):
            continue
        params = action.get("parameters") or {}
        if not isinstance(params, dict):
            params = {}
        placeholder = False
        for value in params.values():
            if isinstance(value, str) and ("<" in value or ">" in value):
                placeholder = True
                break
        if placeholder:
            continue
        cleaned_actions.append(action)
    normalized["actions"] = _canonicalize_actions(cleaned_actions)
    rollback = normalized.get("rollbackActions") or []
    if isinstance(rollback, list):
        normalized["rollbackActions"] = _canonicalize_actions(rollback)
    return normalized


def _rebalance_records(records: List[Dict[str, Any]], target_per_strategy: int, seed: int) -> List[Dict[str, Any]]:
    rng = random.Random(seed)
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for record in records:
        buckets.setdefault(record["strategy"], []).append(record)

    if not buckets:
        return records

    if target_per_strategy <= 0:
        target_per_strategy = max(len(items) for items in buckets.values())

    balanced: List[Dict[str, Any]] = []
    for strategy, items in buckets.items():
        if len(items) >= target_per_strategy:
            balanced.extend(rng.sample(items, target_per_strategy))
        else:
            balanced.extend(items)
            while len([r for r in balanced if r["strategy"] == strategy]) < target_per_strategy:
                balanced.append(rng.choice(items))

    rng.shuffle(balanced)
    return balanced


def _rebalance_actions(
    records: List[Dict[str, Any]],
    target_per_action: int,
    seed: int,
    action_types: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    if not records or target_per_action <= 0:
        return records

    rng = random.Random(seed)
    actions_to_balance = [a for a in (action_types or []) if a]
    if not actions_to_balance:
        return records

    index: Dict[str, List[int]] = {a: [] for a in actions_to_balance}
    for idx, record in enumerate(records):
        for action in record.get("action_types", []):
            if action in index:
                index[action].append(idx)

    balanced = list(records)
    for action, ids in index.items():
        if not ids:
            continue
        current = len(ids)
        if current >= target_per_action:
            continue
        needed = target_per_action - current
        for _ in range(needed):
            balanced.append(records[rng.choice(ids)])

    rng.shuffle(balanced)
    return balanced


def main() -> None:
    parser = argparse.ArgumentParser(description="Build compact seq2seq planner dataset.")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("intelligence/training/data/real_planner_train.jsonl"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("intelligence/training/data/planner_seq2seq_train_canonical.jsonl"),
    )
    parser.add_argument(
        "--prompt-style",
        choices=("compact", "minimal", "seq2seq"),
        default="seq2seq",
        help="Prompt template to use for seq2seq training data.",
    )
    parser.add_argument("--limit", type=int, default=0, help="Limit number of examples (0 = all).")
    parser.add_argument("--rebalance", action="store_true", help="Oversample to balance strategy classes.")
    parser.add_argument(
        "--target-per-strategy",
        type=int,
        default=0,
        help="Target count per strategy when rebalancing (0 = use max class).",
    )
    parser.add_argument(
        "--rebalance-actions",
        action="store_true",
        help="Oversample to balance rare action types (seq2seq only).",
    )
    parser.add_argument(
        "--target-per-action",
        type=int,
        default=400,
        help="Target count per action type when rebalancing actions.",
    )
    parser.add_argument(
        "--action-types",
        type=str,
        default="BlockIp,IsolateHost,QuarantineFile,KillProcess,DisableUser,UnisolateHost,CollectForensics",
        help="Comma-separated action types to rebalance.",
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if not args.input.exists():
        raise FileNotFoundError(f"Input dataset not found: {args.input}")

    kept = 0
    skipped = 0
    records: List[Dict[str, Any]] = []

    with args.input.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            if args.limit and kept >= args.limit:
                break
            record = json.loads(line)
            prompt = record.get("prompt", "")
            completion_raw = record.get("completion", "")

            alert, assessment = _parse_prompt(prompt)
            plan = _parse_completion(completion_raw)

            if not alert or not assessment or not plan:
                skipped += 1
                continue

            normalized = _normalize_plan(plan, alert, assessment)
            if args.prompt_style == "seq2seq":
                compact_prompt = build_planner_prompt_seq2seq(alert, assessment)
            elif args.prompt_style == "compact":
                compact_prompt = build_planner_prompt_compact(alert, assessment, include_raw=False)
            else:
                compact_prompt = build_planner_prompt_minimal(alert, assessment)

            if args.prompt_style == "seq2seq":
                compact_completion = _pipe_completion(normalized)
            else:
                compact_completion = json.dumps(normalized, ensure_ascii=False)
            action_types = [
                a.get("type") for a in normalized.get("actions", []) if isinstance(a, dict) and a.get("type")
            ]

            records.append(
                {
                    "prompt": compact_prompt,
                    "completion": compact_completion,
                    "source": record.get("source"),
                    "alert_type": record.get("alert_type"),
                    "technique_id": record.get("technique_id"),
                    "strategy": normalized.get("strategy"),
                    "action_types": action_types,
                }
            )
            kept += 1

    if args.rebalance and records:
        records = _rebalance_records(records, args.target_per_strategy, args.seed)

    if args.rebalance_actions and records:
        action_types = [a.strip() for a in args.action_types.split(",") if a.strip()]
        records = _rebalance_actions(records, args.target_per_action, args.seed, action_types)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as out:
        for record in records:
            record.pop("strategy", None)
            record.pop("action_types", None)
            out.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(
        f"Saved {len(records)} examples to {args.output} (kept {kept}, skipped {skipped})."
    )


if __name__ == "__main__":
    main()
