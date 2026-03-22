from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..infrastructure.persistence import FileStore
from ..infrastructure.sample_data import seed_if_missing
from ..infrastructure.repositories.events_repo import EventRepository
from ..infrastructure.repositories.weights_repo import WeightRepository
from ..infrastructure.repositories.feedback_repo import FeedbackRepository
from ..infrastructure.repositories.diff_repo import WeightDiffRepository
from ..infrastructure.repositories.traces_repo import TraceRepository
from .services.triage_service import TriageService
from .services.feedback_service import FeedbackService
from .services.trace_service import TraceService
from .services.analytics_service import AnalyticsService
from .demo_seed import seed_feedback_if_empty


@dataclass
class ServiceContainer:
    triage_service: TriageService
    feedback_service: FeedbackService
    trace_service: TraceService
    analytics_service: AnalyticsService
    feedback_repo: FeedbackRepository


def build_container(base_dir: Path) -> ServiceContainer:
    store = FileStore(base_dir)

    event_repo = EventRepository(store)
    weight_repo = WeightRepository(store)
    feedback_repo = FeedbackRepository(store)
    diff_repo = WeightDiffRepository(store)
    trace_repo = TraceRepository(store)

    seed_if_missing(store, event_repo, trace_repo)

    triage_service = TriageService(event_repo, weight_repo)
    feedback_service = FeedbackService(event_repo, weight_repo, feedback_repo, diff_repo)
    trace_service = TraceService(trace_repo)
    analytics_service = AnalyticsService(feedback_repo, diff_repo)

    seed_feedback_if_empty(triage_service, feedback_service, feedback_repo)

    return ServiceContainer(
        triage_service=triage_service,
        feedback_service=feedback_service,
        trace_service=trace_service,
        analytics_service=analytics_service,
        feedback_repo=feedback_repo,
    )


