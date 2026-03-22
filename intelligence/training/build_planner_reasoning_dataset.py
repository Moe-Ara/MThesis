"""Clone planner dataset and inject reasoning into JSON completions.

Takes a compact seq2seq-style prompt + pipe/JSON completion and outputs
JSON completions that include a reasoning block (derived via sanitize_plan).
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from intelligence.core.utils import extract_json, repair_json
from intelligence.planners.plan_utils import sanitize_plan
from intelligence.training.build_planner_seq2seq_dataset import parse_pipe_completion

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

_RE_TYPE = re.compile(r"Type:\s*(.+)")
_RE_SEV_CONF = re.compile(r"Severity:\s*([\d.]+)\s+Confidence:\s*([\d.]+)\s+\((\w+)\)")
_RE_HYPOTHESIS = re.compile(r"Hypothesis:\s*(.+)")
_RE_EVIDENCE = re.compile(r"Evidence:\s*(\[.*\])")
_RE_ENTITIES = re.compile(r"Entities:\s*(\{.*\})")


def _parse_prompt(prompt: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    m_type = _RE_TYPE.search(prompt or "")
    m_sc = _RE_SEV_CONF.search(prompt or "")
    m_hyp = _RE_HYPOTHESIS.search(prompt or "")
    m_ev = _RE_EVIDENCE.search(prompt or "")
    m_ent = _RE_ENTITIES.search(prompt or "")

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
            entities = {}

    hypothesis = m_hyp.group(1).strip() if m_hyp else ""
    evidence = []
    if m_ev:
        try:
            evidence = json.loads(m_ev.group(1))
        except json.JSONDecodeError:
            # Fallback: treat as a single string
            evidence = [m_ev.group(1).strip()]

    alert = {
        "type": alert_type,
        "alertType": alert_type,
        "severity": severity,
        "entities": entities,
    }
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
    text = raw.strip()
    if "|" in text and "strategy=" in text:
        return parse_pipe_completion(text)
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = extract_json(text) or repair_json(text)
        if isinstance(parsed, dict):
            return parsed.get("plan") if isinstance(parsed.get("plan"), dict) else parsed
    parsed = extract_json(text) or repair_json(text)
    if isinstance(parsed, dict):
        return parsed.get("plan") if isinstance(parsed.get("plan"), dict) else parsed
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Clone planner dataset and inject reasoning JSON.")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("intelligence/training/data/planner_seq2seq_train_compact.jsonl"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("intelligence/training/data/planner_seq2seq_train_compact_reasoning.jsonl"),
    )
    args = parser.parse_args()

    if not args.input.exists():
        raise FileNotFoundError(f"Input not found: {args.input}")

    total = 0
    written = 0
    skipped = 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.input.open("r", encoding="utf-8") as src, args.output.open("w", encoding="utf-8") as dst:
        for line in src:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            prompt = record.get("prompt", "")
            completion_raw = record.get("completion", "")
            alert, assessment = _parse_prompt(prompt)
            plan = _parse_completion(completion_raw)
            if not alert or not assessment or not plan:
                skipped += 1
                continue

            source = record.get("source")
            if source:
                alert["sourceSiem"] = source
            technique_id = record.get("technique_id")
            if technique_id:
                alert.setdefault("rawPayload", {})["technique_id"] = technique_id

            sanitized = sanitize_plan(plan, alert, assessment, derive_strategy_from_actions=True)
            out_record = dict(record)
            out_record["completion_original"] = completion_raw
            out_record["completion_format"] = "json_reasoning"
            out_record["completion"] = json.dumps(sanitized, ensure_ascii=False)

            dst.write(json.dumps(out_record, ensure_ascii=False) + "\n")
            written += 1

    log.info("Input: %s", args.input)
    log.info("Output: %s", args.output)
    log.info("Total: %d, Written: %d, Skipped: %d", total, written, skipped)


if __name__ == "__main__":
    main()
