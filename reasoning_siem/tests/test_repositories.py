from datetime import datetime

from reasoning_siem.domain.models import (
    EnrichmentContext,
    EventEnvelope,
    NormalizedEvent,
    WeightChange,
    WeightDiff,
)
from reasoning_siem.infrastructure.persistence import FileStore
from reasoning_siem.infrastructure.repositories.diff_repo import WeightDiffRepository
from reasoning_siem.infrastructure.repositories.events_repo import EventRepository
from reasoning_siem.infrastructure.repositories.feedback_repo import FeedbackRepository
from reasoning_siem.infrastructure.repositories.traces_repo import TraceRepository
from reasoning_siem.infrastructure.repositories.weights_repo import WeightRepository
from reasoning_siem.domain.models import FeedbackEvent, TraceEvent


def test_file_store_roundtrip(tmp_path):
    store = FileStore(tmp_path)

    store.write_json("sample.json", {"a": 1})
    assert store.read_json("sample.json", default=None) == {"a": 1}
    assert store.read_json("missing.json", default={"x": 2}) == {"x": 2}

    store.append_jsonl("events.jsonl", {"id": 1})
    store.append_jsonl("events.jsonl", {"id": 2})
    assert store.read_jsonl("events.jsonl") == [{"id": 1}, {"id": 2}]
    assert store.read_jsonl("missing.jsonl") == []


def test_event_repository_roundtrip(tmp_path):
    store = FileStore(tmp_path)
    repo = EventRepository(store)
    timestamp = datetime(2026, 3, 9, 12, 0, 0)

    envelope = EventEnvelope(
        event=NormalizedEvent(
            event_id="evt-101",
            timestamp=timestamp,
            event_type="malware",
            severity=0.9,
            src_ip="10.0.0.5",
            dest_ip="172.16.0.8",
            user="alice",
            asset_id="srv-app-01",
            failed_logins=0,
            suspicious_processes=2,
            ip_reputation=0.7,
            geo_anomaly=False,
            malware_family="Redline",
            tags=["known_bad"],
        ),
        context=EnrichmentContext(
            asset_criticality=0.7,
            user_privilege=0.4,
            exposure=0.6,
            time_sensitivity=0.8,
        ),
    )

    repo.save_events([envelope])
    events = repo.list_events()

    assert len(events) == 1
    saved = events[0]
    assert saved.event.event_id == "evt-101"
    assert saved.event.malware_family == "Redline"
    assert saved.context.asset_criticality == 0.7


def test_weight_repository_default_and_save(tmp_path):
    store = FileStore(tmp_path)
    repo = WeightRepository(store)

    weights = repo.load()
    assert weights.bias == 6.0
    assert weights.weights

    weights.bias = 8.5
    repo.save(weights)

    reloaded = repo.load()
    assert reloaded.bias == 8.5


def test_feedback_diff_trace_repositories(tmp_path):
    store = FileStore(tmp_path)
    feedback_repo = FeedbackRepository(store)
    diff_repo = WeightDiffRepository(store)
    trace_repo = TraceRepository(store)

    feedback_repo.append(
        FeedbackEvent(
            feedback_id="fb-1",
            incident_id="inc-1",
            analyst="analyst",
            verdict="fp",
            severity_override=1.0,
            timestamp=datetime(2026, 3, 9, 10, 0, 0),
            predicted_risk=55.0,
        )
    )

    diff_repo.append(
        WeightDiff(
            diff_id="diff-1",
            feedback_id="fb-1",
            timestamp=datetime(2026, 3, 9, 10, 5, 0),
            changes=[WeightChange(feature="severity", old=18.0, new=16.0, delta=-2.0)],
        )
    )

    trace_repo.append(
        TraceEvent(
            trace_id="trace-1",
            incident_id="inc-1",
            analyst="analyst",
            action="open_incident",
            timestamp=datetime(2026, 3, 9, 9, 0, 0),
        )
    )

    assert len(feedback_repo.list_events()) == 1
    assert len(diff_repo.list_diffs()) == 1
    assert len(trace_repo.list_traces_for_incident("inc-1")) == 1
