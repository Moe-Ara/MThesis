from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List

from .models import Recommendation, TraceEvent


@dataclass(frozen=True)
class TransitionModel:
    transitions: Dict[str, Counter]
    start_counts: Counter


class TraceRecommender:
    def build_model(self, traces: Iterable[TraceEvent]) -> TransitionModel:
        by_incident: Dict[str, List[TraceEvent]] = defaultdict(list)
        for trace in traces:
            by_incident[trace.incident_id].append(trace)

        transitions: Dict[str, Counter] = defaultdict(Counter)
        start_counts: Counter = Counter()

        for sequence in by_incident.values():
            if not sequence:
                continue
            ordered = sorted(sequence, key=lambda item: item.timestamp)
            start_counts[ordered[0].action] += 1
            for current, nxt in zip(ordered, ordered[1:]):
                transitions[current.action][nxt.action] += 1

        return TransitionModel(transitions=dict(transitions), start_counts=start_counts)

    def recommend(self, last_action: str | None, model: TransitionModel, limit: int = 5) -> List[Recommendation]:
        if last_action and last_action in model.transitions:
            counter = model.transitions[last_action]
        else:
            counter = model.start_counts
        recommendations = [Recommendation(action=action, count=count) for action, count in counter.most_common(limit)]
        return recommendations


