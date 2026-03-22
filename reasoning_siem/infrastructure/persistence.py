from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


class FileStore:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def read_json(self, filename: str, default: Any) -> Any:
        path = self.base_dir / filename
        if not path.exists():
            return default
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def write_json(self, filename: str, payload: Any) -> None:
        path = self.base_dir / filename
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        tmp_path.replace(path)

    def append_jsonl(self, filename: str, record: dict) -> None:
        path = self.base_dir / filename
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    def read_jsonl(self, filename: str) -> Iterable[dict]:
        path = self.base_dir / filename
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]


