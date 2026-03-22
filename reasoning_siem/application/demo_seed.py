from __future__ import annotations

from .services.feedback_service import FeedbackService
from .services.triage_service import TriageService
from ..infrastructure.repositories.feedback_repo import FeedbackRepository


def seed_feedback_if_empty(
    triage_service: TriageService,
    feedback_service: FeedbackService,
    feedback_repo: FeedbackRepository,
) -> None:
    if feedback_repo.list_events():
        return
    incidents = triage_service.get_ranked_incidents()
    if len(incidents) < 2:
        return

    feedback_service.apply_feedback(
        incident_id=incidents[0].incident_id,
        verdict="fp",
        severity_override=1.1,
        analyst="seed",
    )
    feedback_service.apply_feedback(
        incident_id=incidents[1].incident_id,
        verdict="tp",
        severity_override=1.0,
        analyst="seed",
    )


