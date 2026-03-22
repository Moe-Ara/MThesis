from datetime import datetime

from reasoning_siem.application.services.triage_service import TriageService
from reasoning_siem.domain.models import EnrichmentContext, EventEnvelope, NormalizedEvent
from reasoning_siem.infrastructure.persistence import FileStore
from reasoning_siem.infrastructure.repositories.events_repo import EventRepository
from reasoning_siem.infrastructure.repositories.weights_repo import WeightRepository


def _build_event(event_id: str, event_type: str, severity: float) -> EventEnvelope:
    return EventEnvelope(
        event=NormalizedEvent(
            event_id=event_id,
            timestamp=datetime(2026, 3, 9, 12, 0, 0),
            event_type=event_type,
            severity=severity,
            src_ip="10.0.0.5",
            dest_ip="172.16.0.8",
            user="alice",
            asset_id="srv-app-01",
            failed_logins=2,
            suspicious_processes=2,
            ip_reputation=0.7,
            geo_anomaly=False,
            malware_family=None,
            tags=[],
        ),
        context=EnrichmentContext(
            asset_criticality=0.6,
            user_privilege=0.4,
            exposure=0.4,
            time_sensitivity=0.5,
        ),
    )


def test_triage_ranks_higher_risk_first(tmp_path):
    store = FileStore(tmp_path)
    event_repo = EventRepository(store)
    weight_repo = WeightRepository(store)

    high = _build_event("evt-201", "malware", 0.9)
    low = _build_event("evt-202", "auth_failure", 0.2)
    event_repo.save_events([low, high])

    triage = TriageService(event_repo, weight_repo)
    ranked = triage.get_ranked_incidents()

    assert ranked
    assert ranked[0].event_id == "evt-201"

    incident = triage.get_incident("inc-evt-202")
    assert incident is not None
    assert incident.event_id == "evt-202"
