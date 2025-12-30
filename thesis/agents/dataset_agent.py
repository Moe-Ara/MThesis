"""Agent responsible for building and maintaining the dataset CSV."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from thesis.agents.base import Agent
from thesis.blackboard.core import Blackboard
from thesis.dataset.builder import CsvDatasetBuilder


class DatasetAgent(Agent):
    """Wraps CsvDatasetBuilder and exposes ingestion helpers."""

    name = "dataset"

    def __init__(self, builder: CsvDatasetBuilder, board: Optional[Blackboard] = None) -> None:
        self.builder = builder
        self.board = board

    def run(
        self,
        *,
        log_paths: Sequence[Path],
        dedup: bool = False,
    ) -> Dict[str, Any]:
        """Load logs and append them to the CSV, optionally deduplicating afterwards."""

        logs: List[Dict[str, Any]] = []
        for path in log_paths:
            logs.extend(self.builder.load_json_logs(path))

        added_rows = self.builder.append_logs(logs)
        duplicates = self.builder.deduplicate() if dedup else 0
        if self.board is not None:
            self.board.set(
                "last_dataset_stats",
                {"added_rows": added_rows, "duplicates_removed": duplicates},
            )

        return {
            "added_rows": added_rows,
            "duplicates_removed": duplicates,
            "log_sources": [str(path) for path in log_paths],
        }

    def ingest(
        self,
        log_paths: Sequence[Path],
        dedup: bool = False,
    ) -> Dict[str, Any]:
        """Compatibility helper that delegates to `run`."""

        return self.run(log_paths=log_paths, dedup=dedup)
