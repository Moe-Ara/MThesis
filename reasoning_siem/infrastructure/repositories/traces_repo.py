from __future__ import annotations

from datetime import datetime
from typing import List

from ..persistence import FileStore
from ...domain.models import TraceEvent


class TraceRepository:
    def __init__(self, store: FileStore, filename: str = "trace_log.jsonl"):
        self.store = store
        self.filename = filename

    def append(self, trace: TraceEvent) -> None:
        self.store.append_jsonl(self.filename, self._to_record(trace))

    def list_traces(self) -> List[TraceEvent]:
        records = self.store.read_jsonl(self.filename)
        return [self._from_record(record) for record in records]

    def list_traces_for_incident(self, incident_id: str) -> List[TraceEvent]:
        return [trace for trace in self.list_traces() if trace.incident_id == incident_id]

    def _to_record(self, trace: TraceEvent) -> dict:
        return {
            "trace_id": trace.trace_id,
            "incident_id": trace.incident_id,
            "analyst": trace.analyst,
            "action": trace.action,
            "timestamp": trace.timestamp.isoformat(),
        }

    def _from_record(self, record: dict) -> TraceEvent:
        return TraceEvent(
            trace_id=record["trace_id"],
            incident_id=record["incident_id"],
            analyst=record["analyst"],
            action=record["action"],
            timestamp=datetime.fromisoformat(record["timestamp"]),
        )


