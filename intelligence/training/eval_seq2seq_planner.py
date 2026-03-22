import argparse
import json
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from datasets import load_dataset

from intelligence.core.utils import extract_json
from intelligence.planners.seq2seq import Seq2SeqPlanner
from intelligence.training.build_planner_seq2seq_dataset import _parse_prompt, parse_pipe_completion


def _parse_completion(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    if "|" in raw and "strategy=" in raw:
        return parse_pipe_completion(raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return extract_json(raw)


def _normalize_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    if "plan" in plan and isinstance(plan["plan"], dict):
        return plan["plan"]
    return plan


def _action_types(plan: Optional[Dict[str, Any]]) -> List[str]:
    if not plan or not isinstance(plan, dict):
        return []
    actions = plan.get("actions") or []
    if not isinstance(actions, list):
        return []
    return [a.get("type", "") for a in actions if isinstance(a, dict)]


def _compute_action_overlap(pred: List[str], target: List[str]) -> Dict[str, float]:
    pred_set = set([p for p in pred if p])
    target_set = set([t for t in target if t])
    if not pred_set and not target_set:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    if not pred_set or not target_set:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    overlap = pred_set & target_set
    precision = len(overlap) / len(pred_set)
    recall = len(overlap) / len(target_set)
    if precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def _summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    strategy_hits = 0
    relaxed_hits = 0
    total = 0
    overlaps = []
    for row in results:
        target = row["target"]
        pred = row["pred"]
        if "error" in pred:
            continue
        pred_plan = _normalize_plan(pred)
        target_plan = _normalize_plan(target)
        if not isinstance(pred_plan, dict) or not isinstance(target_plan, dict):
            continue
        if pred_plan.get("strategy") == target_plan.get("strategy"):
            strategy_hits += 1
        pred_strategy = pred_plan.get("strategy")
        target_strategy = target_plan.get("strategy")
        if _relaxed_strategy_match(pred_strategy, target_strategy):
            relaxed_hits += 1
        overlap = _compute_action_overlap(_action_types(pred_plan), _action_types(target_plan))
        overlaps.append(overlap)
        total += 1

    if total == 0:
        return {"strategy_acc": None, "strategy_acc_relaxed": None, "action_f1": None}

    avg_f1 = sum(o["f1"] for o in overlaps) / len(overlaps) if overlaps else None
    return {
        "strategy_acc": strategy_hits / total,
        "strategy_acc_relaxed": relaxed_hits / total,
        "action_f1": avg_f1,
    }


def _relaxed_strategy_match(pred: Optional[str], target: Optional[str]) -> bool:
    if not pred or not target:
        return False
    if pred == target:
        return True
    contain_group = {"Contain", "ContainAndCollect"}
    observe_group = {"ObserveMore", "NotifyOnly"}
    if pred in contain_group and target in contain_group:
        return True
    if pred in observe_group and target in observe_group:
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate seq2seq planner on a dataset split.")
    parser.add_argument(
        "--data",
        type=Path,
        default=Path("intelligence/training/data/planner_seq2seq_train_compact.jsonl"),
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default="intelligence/models/planner_seq2seq",
    )
    parser.add_argument("--limit", type=int, default=0, help="Limit evaluation records (0 = all).")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.1, help="Evaluation split size.")
    parser.add_argument("--output", type=Path, default=Path("intelligence/training/data/seq2seq_eval.json"))
    args = parser.parse_args()

    dataset = load_dataset("json", data_files=str(args.data))["train"]
    split = dataset.train_test_split(test_size=args.test_size, seed=args.seed)
    eval_set = split["test"]
    if args.limit and args.limit > 0:
        eval_set = eval_set.select(range(min(args.limit, len(eval_set))))

    planner = Seq2SeqPlanner(args.model_path, max_new_tokens=256, num_beams=4, temperature=0.0)
    results = []
    for record in eval_set:
        prompt = record.get("prompt", "")
        target = _parse_completion(record.get("completion", "")) or {}
        # Try parsing alert/assessment from prompt (works for verbose prompts).
        # For compact seq2seq prompts, fall back to direct inference with raw prompt.
        alert, assessment = _parse_prompt(prompt)
        try:
            if alert and assessment:
                pred = planner.plan(alert, assessment)
            else:
                pred = planner.plan_from_prompt(prompt)
        except Exception as exc:
            pred = {"error": str(exc)}
        results.append({"target": target, "pred": pred})

    summary = _summarize(results)
    payload = {"summary": summary, "samples": len(results)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
