"""Evaluate the custom NN planner using the same metrics as eval_seq2seq_planner.

Reuses _summarize / _compute_action_overlap / _relaxed_strategy_match from the
seq2seq eval so the results are directly comparable.

IMPORTANT: Both targets and predictions are sanitized through sanitize_plan so
the comparison is apples-to-apples (raw targets include infeasible actions that
sanitize_plan would drop, unfairly penalizing the model).
"""

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

from datasets import load_dataset

from intelligence.planners.custom_nn import CustomNNPlanner
from intelligence.planners.plan_utils import sanitize_plan
from intelligence.training.build_planner_seq2seq_dataset import parse_pipe_completion
from intelligence.training.eval_seq2seq_planner import _summarize

# Rollback actions appear in some targets as regular actions but the NN model
# correctly outputs them in rollbackActions.  Filter them from the comparison.
_ROLLBACK_TYPES = {"UnisolateHost", "UnblockIp", "EnableUser"}


def _strip_rollback_actions(plan: Dict[str, Any], alert: Dict[str, Any],
                            assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Remove rollback action types from the main actions list and re-derive strategy."""
    from intelligence.planners.plan_utils import derive_strategy
    actions = plan.get("actions", [])
    filtered = [a for a in actions if isinstance(a, dict) and a.get("type") not in _ROLLBACK_TYPES]
    if not filtered:
        filtered = [{"type": "OpenTicket", "parameters": {}}]
    result = {**plan, "actions": filtered}
    result["strategy"] = derive_strategy(alert, assessment, result)
    return result

_RE_TYPE = re.compile(r"Type:\s*(.+)")
_RE_SEV_CONF = re.compile(r"Severity:\s*([\d.]+)\s+Confidence:\s*([\d.]+)\s+\((\w+)\)")
_RE_HYPOTHESIS = re.compile(r"Hypothesis:\s*(.+)")
_RE_EVIDENCE = re.compile(r"Evidence:\s*(\[.*\])")
_RE_ENTITIES = re.compile(r"Entities:\s*(\{.*\})")


def _prompt_to_alert_assessment(prompt: str) -> tuple:
    """Reconstruct alert and assessment dicts from a compact seq2seq prompt."""
    m_type = _RE_TYPE.search(prompt)
    m_sc = _RE_SEV_CONF.search(prompt)
    m_hyp = _RE_HYPOTHESIS.search(prompt)
    m_ev = _RE_EVIDENCE.search(prompt)
    m_ent = _RE_ENTITIES.search(prompt)

    if not m_type or not m_sc:
        return None, None

    alert_type = m_type.group(1).strip()
    severity = float(m_sc.group(1))
    confidence = float(m_sc.group(2))

    entities = {}
    if m_ent:
        try:
            entities = json.loads(m_ent.group(1))
        except json.JSONDecodeError:
            pass

    hypothesis = m_hyp.group(1).strip() if m_hyp else ""
    evidence = []
    if m_ev:
        try:
            evidence = json.loads(m_ev.group(1))
        except json.JSONDecodeError:
            pass

    alert = {"type": alert_type, "severity": severity, "entities": entities}
    assessment = {
        "severity": severity,
        "confidence": confidence,
        "hypothesis": hypothesis,
        "evidence": evidence,
    }
    return alert, assessment


def _parse_completion(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    if "|" in raw and "strategy=" in raw:
        return parse_pipe_completion(raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate custom NN planner.")
    parser.add_argument("--data", type=Path,
                        default=Path("intelligence/training/data/planner_seq2seq_train_compact.jsonl"))
    parser.add_argument("--model-path", type=str, default="intelligence/models/planner_nn")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.1)
    parser.add_argument("--output", type=Path, default=Path("intelligence/training/data/nn_eval.json"))
    args = parser.parse_args()

    dataset = load_dataset("json", data_files=str(args.data))["train"]
    split = dataset.train_test_split(test_size=args.test_size, seed=args.seed)
    eval_set = split["test"]
    if args.limit and args.limit > 0:
        eval_set = eval_set.select(range(min(args.limit, len(eval_set))))

    planner = CustomNNPlanner(args.model_path)
    results = []
    for record in eval_set:
        prompt = record.get("prompt", "")
        target_raw = _parse_completion(record.get("completion", "")) or {}
        alert, assessment = _prompt_to_alert_assessment(prompt)
        if not alert or not assessment:
            continue
        # Pass source info so the planner can use it for features
        source = record.get("source", "")
        if source:
            alert["sourceSiem"] = source
        technique_id = record.get("technique_id", "")
        if technique_id:
            alert.setdefault("rawPayload", {})["technique_id"] = technique_id

        # Sanitize the TARGET through the same pipeline as the prediction
        # so the comparison is fair (raw targets include infeasible actions)
        target = sanitize_plan(
            target_raw, alert, assessment, derive_strategy_from_actions=True,
        )

        try:
            pred = planner.plan(alert, assessment)
        except Exception as exc:
            pred = {"error": str(exc)}

        # Strip rollback actions from both sides for fair comparison
        target = _strip_rollback_actions(target, alert, assessment)
        if isinstance(pred, dict) and "error" not in pred:
            pred = _strip_rollback_actions(pred, alert, assessment)

        results.append({"target": target, "pred": pred})

    summary = _summarize(results)
    payload = {"summary": summary, "samples": len(results)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
