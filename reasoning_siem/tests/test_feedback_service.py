from datetime import datetime

from reasoning_siem.application.services.feedback_service import FeedbackService
from reasoning_siem.application.services.triage_service import TriageService
from reasoning_siem.domain.models import EnrichmentContext, EventEnvelope, NormalizedEvent
from reasoning_siem.infrastructure.persistence import FileStore
from reasoning_siem.infrastructure.repositories.diff_repo import WeightDiffRepository
from reasoning_siem.infrastructure.repositories.events_repo import EventRepository
from reasoning_siem.infrastructure.repositories.feedback_repo import FeedbackRepository
from reasoning_siem.infrastructure.repositories.weights_repo import WeightRepository


def _seed_event(event_id: str) -> EventEnvelope:
    event = NormalizedEvent(
        event_id=event_id,
        timestamp=datetime.utcnow(),
        event_type="malware",
        severity=0.92,
        src_ip="10.0.0.9",
        dest_ip="172.16.0.8",
        user="admin_ops",
        asset_id="db-core-02",
        failed_logins=0,
        suspicious_processes=3,
        ip_reputation=0.9,
        geo_anomaly=True,
        malware_family="Redline",
        tags=["known_bad"],
    )
    context = EnrichmentContext(
        asset_criticality=0.9,
        user_privilege=0.8,
        exposure=0.7,
        time_sensitivity=0.9,
    )
    return EventEnvelope(event=event, context=context)


def test_feedback_fp_reduces_risk_and_logs(tmp_path):
    store = FileStore(tmp_path)
    event_repo = EventRepository(store)
    weight_repo = WeightRepository(store)
    feedback_repo = FeedbackRepository(store)
    diff_repo = WeightDiffRepository(store)

    envelope = _seed_event("evt-900")
    event_repo.save_events([envelope])

    triage = TriageService(event_repo, weight_repo)
    incident_id = "inc-evt-900"
    before = triage.get_incident(incident_id)
    assert before is not None

    service = FeedbackService(event_repo, weight_repo, feedback_repo, diff_repo)
    result = service.apply_feedback(
        incident_id=incident_id,
        verdict="fp",
        severity_override=1.0,
        analyst="unit-test",
    )

    assert result is not None
    after = result.incident_after
    assert after.risk_score < before.risk_score

    feedback_events = feedback_repo.list_events()
    diffs = diff_repo.list_diffs()
    assert len(feedback_events) == 1
    assert len(diffs) == 1
    assert diffs[0].changes


def test_feedback_severity_override_is_clamped(tmp_path):
    store = FileStore(tmp_path)
    event_repo = EventRepository(store)
    weight_repo = WeightRepository(store)
    feedback_repo = FeedbackRepository(store)
    diff_repo = WeightDiffRepository(store)

    envelope = _seed_event("evt-901")
    event_repo.save_events([envelope])

    service = FeedbackService(event_repo, weight_repo, feedback_repo, diff_repo)
    service.apply_feedback(
        incident_id="inc-evt-901",
        verdict="tp",
        severity_override=10.0,
        analyst="unit-test",
    )

    feedback_events = feedback_repo.list_events()
    assert feedback_events[0].severity_override == 2.0
