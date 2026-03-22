import json
import re
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


def repair_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None

    parsed = extract_json(text)
    if parsed:
        return parsed

    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start : i + 1]
                candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    return None

    # Try appending missing braces if the object was truncated.
    if depth > 0:
        candidate = text[start:] + ("}" * depth)
        candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            return None

    return None
