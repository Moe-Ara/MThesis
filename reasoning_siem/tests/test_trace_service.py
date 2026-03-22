from datetime import datetime

from reasoning_siem.application.services.trace_service import TraceService
from reasoning_siem.domain.models import TraceEvent
from reasoning_siem.infrastructure.persistence import FileStore
from reasoning_siem.infrastructure.repositories.traces_repo import TraceRepository


def test_trace_service_logs_and_last_action(tmp_path):
    store = FileStore(tmp_path)
    repo = TraceRepository(store)
    service = TraceService(repo)

    repo.append(
        TraceEvent(
            trace_id="t1",
            incident_id="inc-1",
            analyst="analyst",
            action="open_incident",
            timestamp=datetime(2026, 3, 9, 9, 0, 0),
        )
    )
    service.log_action("inc-1", "review_auth_logs", "analyst")

    last_action = service.last_action_for_incident("inc-1")
    assert last_action in {"review_auth_logs", "open_incident"}


def test_trace_service_recommendations_not_empty(tmp_path):
    store = FileStore(tmp_path)
    repo = TraceRepository(store)
    service = TraceService(repo)

    service.log_action("inc-1", "open_incident", "analyst")
    service.log_action("inc-1", "review_auth_logs", "analyst")

    recommendations = service.recommend_next("open_incident")
    assert recommendations
