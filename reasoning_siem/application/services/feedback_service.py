from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from ..domain.models import FeedbackEvent, IncidentCandidate, WeightChange, WeightDiff
from ..domain.scoring import FeatureContext, WeightedScoringModel, clamp
from ..infrastructure.repositories.diff_repo import WeightDiffRepository
from ..infrastructure.repositories.events_repo import EventRepository
from ..infrastructure.repositories.feedback_repo import FeedbackRepository
from ..infrastructure.repositories.weights_repo import WeightRepository
from .triage_service import TriageService


@dataclass(frozen=True)
class FeedbackResult:
    incident_before: IncidentCandidate
    incident_after: IncidentCandidate
    weight_diff: WeightDiff


class FeedbackService:
    def __init__(
        self,
        event_repo: EventRepository,
        weight_repo: WeightRepository,
        feedback_repo: FeedbackRepository,
        diff_repo: WeightDiffRepository,
    ):
        self.event_repo = event_repo
        self.weight_repo = weight_repo
        self.feedback_repo = feedback_repo
        self.diff_repo = diff_repo

    def apply_feedback(
        self,
        incident_id: str,
        verdict: str,
        severity_override: float,
        analyst: str,
    ) -> Optional[FeedbackResult]:
        candidate = self._resolve_candidate(incident_id)
        if not candidate:
            return None

        weight_set = self.weight_repo.load()

        predicted = clamp(candidate.risk_score / 100.0, 0.0, 1.0)
        target = {"tp": 1.0, "fp": 0.0, "nmi": 0.5}.get(verdict, 0.5)

        severity_override = clamp(severity_override, 0.5, 2.0)
        learning_rate = 1.2 * severity_override
        max_step = 3.0 * severity_override
        max_bias_step = 2.0 * severity_override

        error = target - predicted

        changes: List[WeightChange] = []
        new_weights = weight_set.weights.copy()
        for feature, value in candidate.feature_vector.items():
            if value <= 0:
                continue
            old = new_weights.get(feature, 0.0)
            delta = clamp(learning_rate * error * value, -max_step, max_step)
            updated = clamp(old + delta, weight_set.min_weight, weight_set.max_weight)
            if abs(updated - old) > 0.0001:
                changes.append(WeightChange(feature=feature, old=old, new=updated, delta=updated - old))
            new_weights[feature] = updated

        old_bias = weight_set.bias
        bias_delta = clamp(learning_rate * error * 3.0, -max_bias_step, max_bias_step)
        weight_set.bias = clamp(weight_set.bias + bias_delta, weight_set.min_weight, weight_set.max_weight)
        if abs(weight_set.bias - old_bias) > 0.0001:
            changes.append(
                WeightChange(
                    feature="bias",
                    old=old_bias,
                    new=weight_set.bias,
                    delta=weight_set.bias - old_bias,
                )
            )
        weight_set.weights = new_weights
        weight_set.updated_at = datetime.utcnow()
        weight_set.version += 1
        self.weight_repo.save(weight_set)

        feedback_event = FeedbackEvent(
            feedback_id=str(uuid4()),
            incident_id=incident_id,
            analyst=analyst,
            verdict=verdict,
            severity_override=severity_override,
            timestamp=datetime.utcnow(),
            predicted_risk=candidate.risk_score,
        )
        self.feedback_repo.append(feedback_event)

        weight_diff = WeightDiff(
            diff_id=str(uuid4()),
            feedback_id=feedback_event.feedback_id,
            timestamp=feedback_event.timestamp,
            changes=changes,
        )
        self.diff_repo.append(weight_diff)

        updated_candidate = self._resolve_candidate(incident_id)
        if not updated_candidate:
            return None

        return FeedbackResult(
            incident_before=candidate,
            incident_after=updated_candidate,
            weight_diff=weight_diff,
        )

    def _resolve_candidate(self, incident_id: str) -> Optional[IncidentCandidate]:
        triage = TriageService(self.event_repo, self.weight_repo)
        return triage.get_incident(incident_id)


