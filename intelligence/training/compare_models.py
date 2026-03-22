import argparse
import json
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from intelligence.core.utils import extract_json
from intelligence.core.model_registry import ModelRegistry
from intelligence.planners.seq2seq import Seq2SeqPlanner
from intelligence.planners.ollama import OllamaPlanner
from intelligence.scorers.classifier import ClassifierScorer
from intelligence.scorers.ollama import OllamaScorer
from intelligence.scorers.classifier_config import severity_to_class


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
                    return extract_json(snippet)
    return None


def _parse_prompt(prompt: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    alert = None
    assessment = None

    alert_idx = prompt.rfind("Alert:")
    if alert_idx != -1:
        alert = _extract_json_object(prompt, alert_idx)

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


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def _select_records(records: List[Dict[str, Any]], limit: int, seed: int) -> List[Dict[str, Any]]:
    rng = random.Random(seed)
    items = list(records)
    rng.shuffle(items)
    if limit > 0:
        return items[:limit]
    return items


def _safe_score(model, alert: Dict[str, Any]) -> Dict[str, Any]:
    try:
        result = model.score(alert)
        if isinstance(result, dict):
            return result
        return {"error": "invalid scorer response"}
    except Exception as exc:
        return {"error": str(exc)}


def _safe_plan(model, alert: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
    try:
        result = model.plan(alert, assessment)
        if isinstance(result, dict):
            return result
        return {"error": "invalid planner response"}
    except Exception as exc:
        return {"error": str(exc)}


def _summarize_scorer(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    def _metric(name: str) -> Dict[str, float]:
        diffs = []
        cls_hits = 0
        conf_diffs = []
        total = 0
        for row in results:
            target = row["target"]
            pred = row[name]
            if "error" in pred:
                continue
            t_sev = target.get("severity")
            p_sev = pred.get("severity")
            t_conf = target.get("confidence")
            p_conf = pred.get("confidence")
            if isinstance(t_sev, (int, float)) and isinstance(p_sev, (int, float)):
                diffs.append(abs(float(t_sev) - float(p_sev)))
                if severity_to_class(t_sev) == severity_to_class(p_sev):
                    cls_hits += 1
                total += 1
            if isinstance(t_conf, (int, float)) and isinstance(p_conf, (int, float)):
                conf_diffs.append(abs(float(t_conf) - float(p_conf)))
        mae = sum(diffs) / len(diffs) if diffs else None
        cls_acc = cls_hits / total if total else None
        conf_mae = sum(conf_diffs) / len(conf_diffs) if conf_diffs else None
        return {"severity_mae": mae, "severity_class_acc": cls_acc, "confidence_mae": conf_mae}

    return {
        "classifier": _metric("classifier"),
        "foundation_sec": _metric("foundation_sec"),
    }


def _summarize_planner(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    def _metric(name: str) -> Dict[str, float]:
        strategy_hits = 0
        total = 0
        overlaps = []
        for row in results:
            target = row["target"]
            pred = row[name]
            if "error" in pred:
                continue
            pred_plan = _normalize_plan(pred)
            target_plan = _normalize_plan(target)
            if not isinstance(pred_plan, dict) or not isinstance(target_plan, dict):
                continue
            if pred_plan.get("strategy") == target_plan.get("strategy"):
                strategy_hits += 1
            overlap = _compute_action_overlap(_action_types(pred_plan), _action_types(target_plan))
            overlaps.append(overlap)
            total += 1
        if total == 0:
            return {"strategy_acc": None, "action_f1": None}
        avg_f1 = sum(o["f1"] for o in overlaps) / len(overlaps) if overlaps else None
        return {"strategy_acc": strategy_hits / total, "action_f1": avg_f1}

    return {
        "seq2seq": _metric("seq2seq"),
        "foundation_sec": _metric("foundation_sec"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare custom models vs fine-tuned LLMs.")
    parser.add_argument("--scorer-data", type=Path, default=Path("intelligence/training/data/real_scorer_train.jsonl"))
    parser.add_argument("--planner-data", type=Path, default=Path("intelligence/training/data/real_planner_train.jsonl"))
    parser.add_argument("--limit", type=int, default=30, help="Number of samples per task (0 = all).")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--ollama-base", default="http://localhost:11434")
    parser.add_argument("--ollama-scorer", default="foundation-sec-scorer")
    parser.add_argument("--ollama-planner", default="foundation-sec-planner")
    parser.add_argument("--registry", type=Path, default=None, help="Optional model registry JSON.")
    parser.add_argument("--profile", type=str, default=None, help="Registry profile to evaluate.")
    parser.add_argument("--skip-scorer", action="store_true", help="Skip scorer comparison.")
    parser.add_argument("--skip-planner", action="store_true", help="Skip planner comparison.")
    parser.add_argument("--output", type=Path, default=Path("intelligence/training/data/model_compare.json"))
    args = parser.parse_args()

    scorer_records = []
    planner_records = []
    if not args.skip_scorer:
        scorer_records = _select_records(_load_jsonl(args.scorer_data), args.limit, args.seed)
    if not args.skip_planner:
        planner_records = _select_records(_load_jsonl(args.planner_data), args.limit, args.seed)

    scorer_classifier = None
    planner_seq2seq = None
    scorer_ft = None
    planner_ft = None

    if not args.skip_scorer:
        scorer_classifier = ClassifierScorer("intelligence/models/scorer_classifier")

    if not args.skip_planner:
        planner_seq2seq = Seq2SeqPlanner("intelligence/models/planner_seq2seq", max_new_tokens=192, num_beams=4)

    if args.registry and args.registry.exists():
        registry = ModelRegistry.from_file(args.registry, args.profile)
        if not args.skip_scorer:
            scorer_ft = registry.get_scorer(args.profile)
        if not args.skip_planner:
            planner_ft = registry.get_planner(args.profile)
    else:
        if not args.skip_scorer:
            scorer_ft = OllamaScorer(args.ollama_base, args.ollama_scorer, timeout=120)
        if not args.skip_planner:
            planner_ft = OllamaPlanner(args.ollama_base, args.ollama_planner, timeout=180)

    scorer_results = []
    if not args.skip_scorer and scorer_classifier and scorer_ft:
        for record in scorer_records:
            prompt = record.get("prompt", "")
            target = _parse_completion(record.get("completion", "")) or {}
            alert, _ = _parse_prompt(prompt)
            if not alert:
                continue
            scorer_results.append(
                {
                    "alert_type": alert.get("type"),
                    "target": target,
                    "classifier": _safe_score(scorer_classifier, alert),
                    "foundation_sec": _safe_score(scorer_ft, alert),
                }
            )

    planner_results = []
    if not args.skip_planner and planner_seq2seq and planner_ft:
        for record in planner_records:
            prompt = record.get("prompt", "")
            target = _parse_completion(record.get("completion", "")) or {}
            alert, assessment = _parse_prompt(prompt)
            if not alert or not assessment:
                continue
            planner_results.append(
                {
                    "alert_type": alert.get("type"),
                    "target": target,
                    "seq2seq": _safe_plan(planner_seq2seq, alert, assessment),
                    "foundation_sec": _safe_plan(planner_ft, alert, assessment),
                }
            )

    summary = {
        "scorer": _summarize_scorer(scorer_results) if scorer_results else None,
        "planner": _summarize_planner(planner_results) if planner_results else None,
        "counts": {
            "scorer_samples": len(scorer_results),
            "planner_samples": len(planner_results),
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "summary": summary,
                "scorer_results": scorer_results,
                "planner_results": planner_results,
            },
            handle,
            indent=2,
        )

    print(json.dumps(summary, indent=2))
    print(f"\nSaved detailed results to {args.output}")


if __name__ == "__main__":
    main()
