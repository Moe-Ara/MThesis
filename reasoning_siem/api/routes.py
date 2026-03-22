from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from .schemas import FeedbackRequest, TraceRequest
from ..application.container import ServiceContainer


router = APIRouter()


def _services(request: Request) -> ServiceContainer:
    return request.app.state.services


def _serialize_incident(candidate) -> dict:
    return {
        "incident_id": candidate.incident_id,
        "event_id": candidate.event_id,
        "event_type": candidate.event_type,
        "asset_id": candidate.asset_id,
        "user": candidate.user,
        "timestamp": candidate.timestamp.isoformat(),
        "evidence_score": round(candidate.evidence_score, 2),
        "evidence_score_raw": round(candidate.evidence_score_raw, 2),
        "context_multiplier": round(candidate.context_multiplier, 3),
        "context_breakdown": {key: round(val, 3) for key, val in candidate.context_breakdown.items()},
        "confidence": round(candidate.confidence, 3),
        "risk_score": round(candidate.risk_score, 2),
        "top_reasons": [
            {
                "feature": reason.feature,
                "value": round(reason.value, 3),
                "weight": round(reason.weight, 2),
                "contribution": round(reason.contribution, 2),
            }
            for reason in candidate.top_reasons
        ],
        "feature_vector": {key: round(val, 3) for key, val in candidate.feature_vector.items()},
    }


@router.get("/")
async def root() -> RedirectResponse:
    return RedirectResponse(url="/ui/triage")


@router.get("/ui/triage")
async def triage_page(request: Request):
    services = _services(request)
    incidents = services.triage_service.get_ranked_incidents()
    return request.app.state.templates.TemplateResponse(
        "triage.html",
        {"request": request, "incidents": incidents},
    )


@router.get("/ui/incidents/{incident_id}")
async def incident_page(incident_id: str, request: Request):
    services = _services(request)
    incident = services.triage_service.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    last_action = services.trace_service.last_action_for_incident(incident_id)
    recommendations = services.trace_service.recommend_next(last_action)
    return request.app.state.templates.TemplateResponse(
        "incident_detail.html",
        {
            "request": request,
            "incident": incident,
            "last_action": last_action,
            "recommendations": recommendations,
        },
    )


@router.get("/ui/learning")
async def learning_page(request: Request):
    services = _services(request)
    feedback_events = services.feedback_repo.list_events()
    counters = services.analytics_service.counters()
    trend = services.analytics_service.feedback_trend()
    diff_summary = services.analytics_service.weight_change_summary()
    diffs = services.analytics_service.recent_weight_diffs()
    return request.app.state.templates.TemplateResponse(
        "learning.html",
        {
            "request": request,
            "feedback_events": feedback_events,
            "counters": counters,
            "trend": trend,
            "diff_summary": diff_summary,
            "diffs": diffs,
        },
    )


@router.get("/api/triage")
async def triage_api(request: Request):
    services = _services(request)
    incidents = services.triage_service.get_ranked_incidents()
    return {"incidents": [_serialize_incident(item) for item in incidents]}


@router.get("/api/incidents/{incident_id}")
async def incident_api(incident_id: str, request: Request):
    services = _services(request)
    incident = services.triage_service.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _serialize_incident(incident)


@router.post("/api/incidents/{incident_id}/feedback")
async def feedback_api(incident_id: str, payload: FeedbackRequest, request: Request):
    services = _services(request)
    result = services.feedback_service.apply_feedback(
        incident_id=incident_id,
        verdict=payload.verdict,
        severity_override=payload.severity_override or 1.0,
        analyst=payload.analyst or "analyst",
    )
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        "before": _serialize_incident(result.incident_before),
        "after": _serialize_incident(result.incident_after),
        "weight_diff": {
            "diff_id": result.weight_diff.diff_id,
            "feedback_id": result.weight_diff.feedback_id,
            "timestamp": result.weight_diff.timestamp.isoformat(),
            "changes": [
                {
                    "feature": change.feature,
                    "old": round(change.old, 2),
                    "new": round(change.new, 2),
                    "delta": round(change.delta, 2),
                }
                for change in result.weight_diff.changes
            ],
        },
    }


@router.post("/api/incidents/{incident_id}/trace")
async def trace_api(incident_id: str, payload: TraceRequest, request: Request):
    services = _services(request)
    services.trace_service.log_action(
        incident_id=incident_id,
        action=payload.action,
        analyst=payload.analyst or "analyst",
    )
    recommendations = services.trace_service.recommend_next(payload.action)
    return {
        "recommendations": [
            {"action": rec.action, "count": rec.count} for rec in recommendations
        ]
    }


@router.get("/api/incidents/{incident_id}/recommendations")
async def recommendation_api(incident_id: str, request: Request):
    services = _services(request)
    last_action = services.trace_service.last_action_for_incident(incident_id)
    recommendations = services.trace_service.recommend_next(last_action)
    return {
        "last_action": last_action,
        "recommendations": [
            {"action": rec.action, "count": rec.count} for rec in recommendations
        ],
    }


