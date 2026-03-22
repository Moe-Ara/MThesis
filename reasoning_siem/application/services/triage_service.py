from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import List, Optional

from ..domain.models import IncidentCandidate
from ..domain.scoring import FeatureContext, WeightedScoringModel
from ..infrastructure.repositories.events_repo import EventRepository
from ..infrastructure.repositories.weights_repo import WeightRepository


class TriageService:
    def __init__(self, event_repo: EventRepository, weight_repo: WeightRepository):
        self.event_repo = event_repo
        self.weight_repo = weight_repo

    def get_ranked_incidents(self) -> List[IncidentCandidate]:
        envelopes = self.event_repo.list_events()
        if not envelopes:
            return []

        now = max(envelope.event.timestamp for envelope in envelopes)
        window_start = now - timedelta(hours=24)

        asset_counts = Counter(
            envelope.event.asset_id
            for envelope in envelopes
            if envelope.event.timestamp >= window_start
        )
        user_counts = Counter(
            envelope.event.user
            for envelope in envelopes
            if envelope.event.timestamp >= window_start
        )

        weight_set = self.weight_repo.load()
        model = WeightedScoringModel(weight_set)

        candidates: List[IncidentCandidate] = []
        for envelope in envelopes:
            asset_count = max(0, asset_counts[envelope.event.asset_id] - 1)
            user_count = max(0, user_counts[envelope.event.user] - 1)
            feature_context = FeatureContext(
                asset_event_count=asset_count,
                user_event_count=user_count,
                window_hours=24,
            )
            incident_id = f"inc-{envelope.event.event_id}"
            candidate = model.score(envelope, feature_context, incident_id)
            candidates.append(candidate)

        return sorted(candidates, key=lambda item: item.risk_score, reverse=True)

    def get_incident(self, incident_id: str) -> Optional[IncidentCandidate]:
        for candidate in self.get_ranked_incidents():
            if candidate.incident_id == incident_id:
                return candidate
        return None


