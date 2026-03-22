import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"

app = FastAPI(title="Reasoning Console", version="0.2.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


DATA_DIR = Path(os.environ.get("REASONING_DATA_DIR", "data/reasoning"))
WEIGHTS_PATH = DATA_DIR / "weights.json"
FEEDBACK_LOG = DATA_DIR / "feedback.jsonl"
WEIGHT_DIFF_LOG = DATA_DIR / "weight_diffs.jsonl"
TRACE_LOG = DATA_DIR / "investigation_traces.jsonl"

DEFAULT_WEIGHTS = {
    "bias": 0.05,
    "weights": {
        "severity_norm": 0.45,
        "confidence": 0.35,
        "has_src_ip": 0.08,
        "has_host": 0.12,
        "has_user": 0.14,
        "has_process": 0.1,
        "has_file_hash": 0.06,
        "is_privileged": 0.12,
        "asset_criticality_norm": 0.15,
        "exposure": 0.1,
        "time_sensitivity": 0.08,
    },
    "min_weight": -1.0,
    "max_weight": 1.0,
    "updated_at": None,
    "version": 1,
}

SEED_ACTIONS = [
    "open_incident",
    "check_asset_owner",
    "review_auth_logs",
    "check_vpn_logs",
    "check_endpoint_logs",
    "collect_forensics",
    "escalate_tp",
    "close_fp",
    "close_tp",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _load_trace() -> Dict[str, Any]:
    path = os.environ.get("DEMO_TRACE_PATH", "data/demo_trace.json")
    trace_path = Path(path)
    if not trace_path.exists():
        return {"ok": False, "message": f"Trace file not found: {trace_path}"}
    try:
        return json.loads(trace_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"ok": False, "message": f"Invalid JSON in trace file: {exc}"}


def _load_weights() -> Dict[str, Any]:
    _ensure_data_dir()
    if not WEIGHTS_PATH.exists():
        payload = {**DEFAULT_WEIGHTS, "updated_at": _now_iso()}
        WEIGHTS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload
    try:
        payload = json.loads(WEIGHTS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        payload = {**DEFAULT_WEIGHTS, "updated_at": _now_iso()}
    # Backfill missing keys.
    payload.setdefault("bias", DEFAULT_WEIGHTS["bias"])
    payload.setdefault("weights", {})
    for key, value in DEFAULT_WEIGHTS["weights"].items():
        payload["weights"].setdefault(key, value)
    payload.setdefault("min_weight", DEFAULT_WEIGHTS["min_weight"])
    payload.setdefault("max_weight", DEFAULT_WEIGHTS["max_weight"])
    payload.setdefault("version", 1)
    payload.setdefault("updated_at", _now_iso())
    return payload


def _save_weights(payload: Dict[str, Any]) -> None:
    _ensure_data_dir()
    WEIGHTS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    _ensure_data_dir()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def _read_jsonl(path: Path, limit: int = 200) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if limit and len(rows) > limit:
        return rows[-limit:]
    return rows


def _ensure_seed_traces() -> None:
    if TRACE_LOG.exists():
        return
    seed_incident = "seed-incident"
    ts = datetime.now(timezone.utc)
    for idx, action in enumerate(
        ["open_incident", "review_auth_logs", "check_endpoint_logs", "collect_forensics", "escalate_tp"]
    ):
        _append_jsonl(
            TRACE_LOG,
            {
                "trace_id": uuid.uuid4().hex,
                "incident_id": seed_incident,
                "analyst": "seed",
                "action": action,
                "timestamp": (ts.replace(microsecond=0) if idx == 0 else ts).isoformat(),
            },
        )


def _extract_features(trace: Dict[str, Any]) -> Dict[str, float]:
    assessment = trace.get("assessment") or {}
    enriched = trace.get("enriched") or {}
    base = enriched.get("base") or {}
    entities = base.get("entities") or {}
    context = enriched.get("context") or {}
    asset = context.get("asset") or {}
    identity = context.get("identity") or {}
    tags = context.get("tags") or {}

    severity = float(assessment.get("severity") or base.get("severity") or 0)
    confidence = float(assessment.get("confidence") or 0)

    def clamp(val: float, lo: float = 0.0, hi: float = 1.0) -> float:
        return max(lo, min(hi, val))

    severity_norm = clamp(severity / 100.0)
    confidence_norm = clamp(confidence)
    asset_criticality_norm = clamp(float(asset.get("criticality", 50)) / 100.0)
    exposure_norm = clamp(float(asset.get("exposure", tags.get("exposure", 0.5))))
    time_norm = clamp(float(tags.get("time_sensitivity", severity_norm)))

    return {
        "severity_norm": severity_norm,
        "confidence": confidence_norm,
        "has_src_ip": 1.0 if entities.get("srcIp") or entities.get("src_ip") else 0.0,
        "has_host": 1.0 if entities.get("hostId") or entities.get("hostname") else 0.0,
        "has_user": 1.0 if entities.get("username") or entities.get("userId") else 0.0,
        "has_process": 1.0 if entities.get("processName") or entities.get("processPath") else 0.0,
        "has_file_hash": 1.0 if entities.get("fileHash") else 0.0,
        "is_privileged": 1.0 if identity.get("privileged") else 0.0,
        "asset_criticality_norm": asset_criticality_norm,
        "exposure": exposure_norm,
        "time_sensitivity": time_norm,
    }


def _compute_context_multiplier(features: Dict[str, float]) -> Tuple[float, Dict[str, float]]:
    asset = 0.8 + features["asset_criticality_norm"] * 0.6
    privilege = 1.2 if features["is_privileged"] > 0 else 1.0
    exposure = 0.9 + features["exposure"] * 0.4
    time_sensitivity = 0.9 + features["time_sensitivity"] * 0.4
    multiplier = asset * privilege * exposure * time_sensitivity
    multiplier = max(0.7, min(2.0, multiplier))
    return multiplier, {
        "asset_criticality": round(asset, 3),
        "user_privilege": round(privilege, 3),
        "exposure": round(exposure, 3),
        "time_sensitivity": round(time_sensitivity, 3),
    }


def _compute_reasoning(trace: Dict[str, Any]) -> Dict[str, Any]:
    weights = _load_weights()
    features = _extract_features(trace)
    bias = float(weights.get("bias", 0.0))
    weight_map = weights.get("weights", {})

    linear = bias
    contributions = []
    for name, value in features.items():
        w = float(weight_map.get(name, 0.0))
        contribution = w * value
        linear += contribution
        contributions.append(
            {
                "feature": name,
                "value": round(value, 3),
                "weight": round(w, 3),
                "contribution": round(contribution, 3),
            }
        )

    evidence_score_raw = max(0.0, min(100.0, linear * 100.0))
    confidence = float((trace.get("assessment") or {}).get("confidence") or 0.0)
    context_multiplier, context_breakdown = _compute_context_multiplier(features)
    risk_score = evidence_score_raw * context_multiplier * confidence
    risk_score = max(0.0, min(100.0, risk_score))

    top_reasons = sorted(contributions, key=lambda x: abs(x["contribution"]), reverse=True)[:6]

    return {
        "evidence_score_raw": round(evidence_score_raw, 2),
        "context_multiplier": round(context_multiplier, 3),
        "context_breakdown": context_breakdown,
        "confidence": round(confidence, 3),
        "risk_score": round(risk_score, 2),
        "top_reasons": top_reasons,
        "weights_version": weights.get("version", 1),
        "weights_updated_at": weights.get("updated_at"),
    }


def _feedback_history(limit: int = 20) -> List[Dict[str, Any]]:
    return list(reversed(_read_jsonl(FEEDBACK_LOG, limit=limit)))


def _weight_diff_history(limit: int = 10) -> List[Dict[str, Any]]:
    return list(reversed(_read_jsonl(WEIGHT_DIFF_LOG, limit=limit)))


def _update_weights(verdict: str, severity_override: float, analyst: str, trace: Dict[str, Any]) -> Dict[str, Any]:
    weights = _load_weights()
    features = _extract_features(trace)
    min_w = float(weights.get("min_weight", -1.0))
    max_w = float(weights.get("max_weight", 1.0))
    lr = 0.05 * max(0.5, min(2.0, severity_override))

    verdict_key = verdict.lower()
    if verdict_key in ("true_positive", "tp"):
        error = 1.0
    elif verdict_key in ("false_positive", "fp"):
        error = -1.0
    else:
        error = -0.2

    changes = []
    weight_map = weights.get("weights", {})
    for name, value in features.items():
        if value <= 0:
            continue
        old = float(weight_map.get(name, 0.0))
        delta = lr * error * value
        new = max(min_w, min(max_w, old + delta))
        if abs(new - old) < 1e-4:
            continue
        weight_map[name] = new
        changes.append(
            {
                "feature": name,
                "old": round(old, 4),
                "new": round(new, 4),
                "delta": round(new - old, 4),
            }
        )

    old_bias = float(weights.get("bias", 0.0))
    bias_delta = lr * error * 0.1
    new_bias = max(min_w, min(max_w, old_bias + bias_delta))
    if abs(new_bias - old_bias) >= 1e-4:
        weights["bias"] = new_bias
        changes.append(
            {
                "feature": "bias",
                "old": round(old_bias, 4),
                "new": round(new_bias, 4),
                "delta": round(new_bias - old_bias, 4),
            }
        )

    weights["weights"] = weight_map
    weights["version"] = int(weights.get("version", 1)) + 1
    weights["updated_at"] = _now_iso()
    _save_weights(weights)

    feedback_id = uuid.uuid4().hex
    incident_id = trace.get("correlationId") or (trace.get("rawAlert") or {}).get("alertId") or "demo"
    predicted_risk = _compute_reasoning(trace).get("risk_score", 0.0)
    _append_jsonl(
        FEEDBACK_LOG,
        {
            "feedback_id": feedback_id,
            "incident_id": incident_id,
            "analyst": analyst,
            "verdict": verdict,
            "severity_override": round(severity_override, 2),
            "timestamp": _now_iso(),
            "predicted_risk": predicted_risk,
        },
    )

    diff_id = uuid.uuid4().hex
    diff_record = {
        "diff_id": diff_id,
        "feedback_id": feedback_id,
        "timestamp": _now_iso(),
        "changes": changes,
    }
    _append_jsonl(WEIGHT_DIFF_LOG, diff_record)
    return diff_record


def _build_transition_model() -> Dict[str, Dict[str, int]]:
    _ensure_seed_traces()
    transitions: Dict[str, Dict[str, int]] = {}
    traces = _read_jsonl(TRACE_LOG, limit=5000)
    traces.sort(key=lambda x: x.get("timestamp", ""))

    by_incident: Dict[str, List[Dict[str, Any]]] = {}
    for item in traces:
        incident = item.get("incident_id", "demo")
        by_incident.setdefault(incident, []).append(item)

    for actions in by_incident.values():
        for idx in range(len(actions) - 1):
            current = actions[idx].get("action")
            nxt = actions[idx + 1].get("action")
            if not current or not nxt:
                continue
            transitions.setdefault(current, {})
            transitions[current][nxt] = transitions[current].get(nxt, 0) + 1

    return transitions


def _last_action_for_incident(incident_id: str) -> Optional[str]:
    traces = _read_jsonl(TRACE_LOG, limit=5000)
    candidates = [t for t in traces if t.get("incident_id") == incident_id]
    if not candidates:
        return None
    candidates.sort(key=lambda x: x.get("timestamp", ""))
    return candidates[-1].get("action")


def _recommend_next(last_action: Optional[str], limit: int = 5) -> List[Dict[str, Any]]:
    transitions = _build_transition_model()
    if last_action and last_action in transitions:
        ranked = sorted(transitions[last_action].items(), key=lambda x: x[1], reverse=True)
        return [{"action": action, "count": count} for action, count in ranked[:limit]]

    # fallback: global most common next actions
    aggregate: Dict[str, int] = {}
    for nxts in transitions.values():
        for action, count in nxts.items():
            aggregate[action] = aggregate.get(action, 0) + count
    ranked = sorted(aggregate.items(), key=lambda x: x[1], reverse=True)
    if ranked:
        return [{"action": action, "count": count} for action, count in ranked[:limit]]
    return [{"action": action, "count": 0} for action in SEED_ACTIONS[:limit]]


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/trace")
def trace() -> JSONResponse:
    return JSONResponse(_load_trace())


@app.get("/api/console")
def console() -> JSONResponse:
    trace_data = _load_trace()
    if trace_data.get("ok") is False:
        return JSONResponse({"ok": False, "message": trace_data.get("message")})

    reasoning = _compute_reasoning(trace_data)
    incident_id = trace_data.get("correlationId") or (trace_data.get("rawAlert") or {}).get("alertId") or "demo"
    last_action = _last_action_for_incident(incident_id)
    recommendations = _recommend_next(last_action)

    model_info = {
        "scorer_profile": os.environ.get("THREAT_SCORER_MODEL_PROFILE")
        or os.environ.get("INTEL_MODEL_PROFILE")
        or os.environ.get("INTEL_ACTIVE_PROFILE")
        or "unknown",
        "planner_profile": os.environ.get("PLANNER_MODEL_PROFILE")
        or os.environ.get("INTEL_MODEL_PROFILE")
        or os.environ.get("INTEL_ACTIVE_PROFILE")
        or "unknown",
    }

    return JSONResponse(
        {
            "ok": True,
            "trace": trace_data,
            "reasoning": reasoning,
            "model": model_info,
            "feedback": {
                "events": _feedback_history(),
                "diffs": _weight_diff_history(),
            },
            "recommendations": {
                "last_action": last_action,
                "items": recommendations,
            },
        }
    )


@app.post("/api/feedback")
async def feedback(request: Request) -> JSONResponse:
    payload = await request.json()
    verdict = str(payload.get("verdict", "needs_more_info"))
    severity_override = float(payload.get("severity_override", 1.0))
    analyst = str(payload.get("analyst", "analyst"))

    trace_data = _load_trace()
    if trace_data.get("ok") is False:
        return JSONResponse({"ok": False, "message": trace_data.get("message")}, status_code=400)

    diff = _update_weights(verdict, severity_override, analyst, trace_data)
    reasoning = _compute_reasoning(trace_data)

    return JSONResponse(
        {
            "ok": True,
            "diff": diff,
            "reasoning": reasoning,
        }
    )


@app.post("/api/trace-action")
async def trace_action(request: Request) -> JSONResponse:
    payload = await request.json()
    action = str(payload.get("action", "")).strip()
    analyst = str(payload.get("analyst", "analyst"))
    if not action:
        return JSONResponse({"ok": False, "message": "action is required"}, status_code=400)

    trace_data = _load_trace()
    if trace_data.get("ok") is False:
        return JSONResponse({"ok": False, "message": trace_data.get("message")}, status_code=400)

    incident_id = trace_data.get("correlationId") or (trace_data.get("rawAlert") or {}).get("alertId") or "demo"
    _append_jsonl(
        TRACE_LOG,
        {
            "trace_id": uuid.uuid4().hex,
            "incident_id": incident_id,
            "analyst": analyst,
            "action": action,
            "timestamp": _now_iso(),
        },
    )
    recommendations = _recommend_next(action)
    return JSONResponse({"ok": True, "recommendations": recommendations})


def main() -> None:
    import uvicorn

    host = os.environ.get("DEMO_UI_HOST", "127.0.0.1")
    port = int(os.environ.get("DEMO_UI_PORT", "8099"))
    uvicorn.run("demo_ui.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
