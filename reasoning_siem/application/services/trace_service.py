from __future__ import annotations

from datetime import datetime
from typing import List
from uuid import uuid4

from ..domain.models import Recommendation, TraceEvent
from ..domain.recommender import TraceRecommender
from ..infrastructure.repositories.traces_repo import TraceRepository


class TraceService:
    def __init__(self, trace_repo: TraceRepository):
        self.trace_repo = trace_repo
        self.recommender = TraceRecommender()

    def log_action(self, incident_id: str, action: str, analyst: str) -> None:
        trace = TraceEvent(
            trace_id=str(uuid4()),
            incident_id=incident_id,
            analyst=analyst,
            action=action,
            timestamp=datetime.utcnow(),
        )
        self.trace_repo.append(trace)

    def recommend_next(self, last_action: str | None) -> List[Recommendation]:
        model = self.recommender.build_model(self.trace_repo.list_traces())
        return self.recommender.recommend(last_action, model)

    def last_action_for_incident(self, incident_id: str) -> str | None:
        traces = self.trace_repo.list_traces_for_incident(incident_id)
        if not traces:
            return None
        ordered = sorted(traces, key=lambda item: item.timestamp)
        return ordered[-1].action


