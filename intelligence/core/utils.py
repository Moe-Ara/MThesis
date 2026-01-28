import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def get_path(obj: Dict[str, Any], path: str) -> Optional[Any]:
    parts = path.split(".")
    cur: Any = obj
    for part in parts:
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def extract_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    candidate = text[start : end + 1]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None
