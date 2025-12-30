"""CSV dataset builder utilities moved into the Thesis package."""

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


class CsvDatasetBuilder:
    """Incrementally build a CSV dataset from JSON logs."""

    def __init__(
        self,
        path: Path,
        fieldnames: Sequence[str],
        unique_fields: Optional[Sequence[str]] = None,
    ) -> None:
        self._path = path
        self._fieldnames = list(fieldnames)
        self._unique_fields = list(unique_fields or self._fieldnames)

    def ensure_database(self) -> None:
        """Create the CSV file with headers when missing."""
        if not self._path.exists():
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self._fieldnames)
                writer.writeheader()

    def append_logs(self, logs: Iterable[Dict[str, Any]]) -> int:
        """Append the provided logs while deduplicating against prior rows."""
        self.ensure_database()
        existing_rows = list(self._read_all_rows())
        seen = {self._signature(row) for row in existing_rows}
        new_rows = []
        for log in logs:
            row = self._prepare_row(log)
            signature = self._signature(row)
            if signature in seen:
                continue
            seen.add(signature)
            new_rows.append(row)

        if new_rows:
            with self._path.open("a", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self._fieldnames)
                writer.writerows(new_rows)

        return len(new_rows)

    def deduplicate(self) -> int:
        """Rewrite the CSV file keeping only the first occurrence of each signature."""
        if not self._path.exists():
            return 0

        rows = list(self._read_all_rows())
        unique: Dict[Tuple[str, ...], Dict[str, str]] = {}
        for row in rows:
            signature = self._signature(row)
            if signature not in unique:
                unique[signature] = row

        duplicates_removed = len(rows) - len(unique)
        if duplicates_removed:
            with self._path.open("w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self._fieldnames)
                writer.writeheader()
                writer.writerows(unique.values())

        return duplicates_removed

    def _read_all_rows(self) -> Iterable[Dict[str, str]]:
        if not self._path.exists():
            return []
        with self._path.open("r", newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            return list(reader)

    def _prepare_row(self, log: Dict[str, Any]) -> Dict[str, str]:
        return {
            field: self._serialize_value(log.get(field, "")) for field in self._fieldnames
        }

    def _signature(self, row: Dict[str, str]) -> Tuple[str, ...]:
        return tuple(row.get(field, "") for field in self._unique_fields)

    @staticmethod
    def _serialize_value(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        return str(value)

    @classmethod
    def load_json_logs(cls, path: Path) -> List[Dict[str, Any]]:
        """Load logs from a JSON file that contains either an object or array."""
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return [
                json.loads(line)
                for line in raw.splitlines()
                if line.strip()
            ]

        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        raise ValueError("Log file must contain a JSON object or array.")
