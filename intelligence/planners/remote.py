from typing import Any, Dict, Optional

import requests

from intelligence.core.base import Planner
from intelligence.core.utils import get_path, now_iso


class RemotePlanner(Planner):
    def __init__(self, base_url: str, api_key: Optional[str], timeout: float, header: str, prefix: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.header = header
        self.prefix = prefix

    def plan(self, alert: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "alert": alert,
            "assessment": assessment,
            "planning": {
                "environment": get_path(alert, "context.environment") or "unknown",
                "dryRun": False,
                "nowUtc": now_iso(),
            },
        }
        headers: Dict[str, str] = {}
        if self.api_key:
            headers[self.header] = f"{self.prefix} {self.api_key}".strip()

        resp = requests.post(
            f"{self.base_url}/v1/plan",
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("plan") or data
