from __future__ import annotations

from datetime import datetime
from typing import List

from ..persistence import FileStore
from ...domain.models import FeedbackEvent


class FeedbackRepository:
    def __init__(self, store: FileStore, filename: str = "feedback_log.jsonl"):
        self.store = store
        self.filename = filename

    def append(self, event: FeedbackEvent) -> None:
        self.store.append_jsonl(self.filename, self._to_record(event))

    def list_events(self) -> List[FeedbackEvent]:
        records = self.store.read_jsonl(self.filename)
        return [self._from_record(record) for record in records]

    def _to_record(self, event: FeedbackEvent) -> dict:
        return {
            "feedback_id": event.feedback_id,
            "incident_id": event.incident_id,
            "analyst": event.analyst,
            "verdict": event.verdict,
            "severity_override": event.severity_override,
            "timestamp": event.timestamp.isoformat(),
            "predicted_risk": event.predicted_risk,
        }

    def _from_record(self, record: dict) -> FeedbackEvent:
        return FeedbackEvent(
            feedback_id=record["feedback_id"],
            incident_id=record["incident_id"],
            analyst=record["analyst"],
            verdict=record["verdict"],
            severity_override=record["severity_override"],
            timestamp=datetime.fromisoformat(record["timestamp"]),
            predicted_risk=record.get("predicted_risk", 0.0),
        )


