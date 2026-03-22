from __future__ import annotations

from datetime import datetime
from typing import List

from ..persistence import FileStore
from ...domain.models import WeightChange, WeightDiff


class WeightDiffRepository:
    def __init__(self, store: FileStore, filename: str = "weight_diff_log.jsonl"):
        self.store = store
        self.filename = filename

    def append(self, diff: WeightDiff) -> None:
        self.store.append_jsonl(self.filename, self._to_record(diff))

    def list_diffs(self) -> List[WeightDiff]:
        records = self.store.read_jsonl(self.filename)
        return [self._from_record(record) for record in records]

    def _to_record(self, diff: WeightDiff) -> dict:
        return {
            "diff_id": diff.diff_id,
            "feedback_id": diff.feedback_id,
            "timestamp": diff.timestamp.isoformat(),
            "changes": [
                {
                    "feature": change.feature,
                    "old": change.old,
                    "new": change.new,
                    "delta": change.delta,
                }
                for change in diff.changes
            ],
        }

    def _from_record(self, record: dict) -> WeightDiff:
        return WeightDiff(
            diff_id=record["diff_id"],
            feedback_id=record["feedback_id"],
            timestamp=datetime.fromisoformat(record["timestamp"]),
            changes=[
                WeightChange(
                    feature=change["feature"],
                    old=change["old"],
                    new=change["new"],
                    delta=change["delta"],
                )
                for change in record.get("changes", [])
            ],
        )


