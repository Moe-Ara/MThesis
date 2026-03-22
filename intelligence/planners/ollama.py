import json
from typing import Any, Dict, List, Optional

import requests

from intelligence.core.base import Planner
from intelligence.core.utils import extract_json, repair_json
from intelligence.planners.plan_utils import sanitize_plan
from intelligence.planners.prompting import build_planner_prompt_compact
from intelligence.planners.rule import RulePlanner


class OllamaPlanner(Planner):
    def __init__(
        self,
        base_url: str,
        model: str,
        timeout: float,
        temperature: float = 0.05,
        top_p: float = 0.9,
        num_predict: Optional[int] = None,
        repeat_penalty: Optional[float] = None,
        json_mode: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self.top_p = top_p
        self.num_predict = num_predict
        self.repeat_penalty = repeat_penalty
        self.json_mode = json_mode
        self._system_prompt = (
            "You are a SOC response planner. "
            "Return ONLY a valid JSON object that matches the planner schema. "
            "Use double quotes for all keys/strings. "
            "Numbers must be numbers (not strings). Booleans must be true/false (not strings). "
            "Always include all required keys, even if empty (e.g., parameters, rollbackActions, rationale, tags). "
            "Actions must be 1-4 items and include OpenTicket or Notify. "
            "No markdown, no extra text."
        )

    def plan(self, alert: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
        prompt = build_planner_prompt_compact(alert, assessment, include_raw=False)
        content = self._chat(prompt)
        parsed = self._parse_plan(content)
        if not parsed:
            repaired = self._repair_json_with_model(content, missing_fields=None)
            parsed = self._parse_plan(repaired)
        if not parsed:
            return RulePlanner().plan(alert, assessment)

        normalized = self._normalize_plan(parsed)
        self._coerce_plan_types(normalized)
        missing = self._missing_fields(normalized)
        if missing:
            repaired = self._repair_json_with_model(json.dumps(normalized, ensure_ascii=False), missing)
            parsed = self._parse_plan(repaired)
            if parsed:
                normalized = self._normalize_plan(parsed)
                self._coerce_plan_types(normalized)
        return sanitize_plan(normalized, alert, assessment, derive_strategy_from_actions=True)

    def _chat(self, prompt: str) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self._system_prompt},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }
        options = self._build_options()
        if options:
            payload["options"] = options
        if self.json_mode:
            payload["format"] = "json"
        resp = requests.post(
            f"{self.base_url}/api/chat",
            json=payload,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["message"]["content"].strip()

    @staticmethod
    def _normalize_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
        if "plan" in plan and isinstance(plan["plan"], dict):
            return plan["plan"]
        return plan

    def _parse_plan(self, text: str) -> Optional[Dict[str, Any]]:
        parsed = extract_json(text) or repair_json(text)
        if parsed and isinstance(parsed, dict):
            return parsed
        return None

    def _missing_fields(self, plan: Dict[str, Any]) -> List[str]:
        required = [
            "planId",
            "strategy",
            "priority",
            "summary",
            "actions",
            "rollbackActions",
            "rationale",
            "tags",
        ]
        missing = [key for key in required if key not in plan]

        actions = plan.get("actions")
        if not isinstance(actions, list):
            if "actions" not in missing:
                missing.append("actions")
            return missing

        action_required = ["type", "risk", "expectedImpact", "reversible", "parameters", "rationale"]
        for index, action in enumerate(actions):
            if not isinstance(action, dict):
                missing.append(f"actions[{index}]")
                continue
            for key in action_required:
                if key not in action:
                    missing.append(f"actions[{index}].{key}")
        return missing

    @staticmethod
    def _coerce_plan_types(plan: Dict[str, Any]) -> None:
        def _to_int(value: Any, default: int = 0) -> int:
            try:
                return int(round(float(value)))
            except (TypeError, ValueError):
                return default

        def _to_bool(value: Any) -> bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.strip().lower() in ("true", "1", "yes")
            return bool(value)

        if "priority" in plan:
            plan["priority"] = _to_int(plan.get("priority"))

        actions = plan.get("actions")
        if isinstance(actions, list):
            for action in actions:
                if not isinstance(action, dict):
                    continue
                if "risk" in action:
                    action["risk"] = _to_int(action.get("risk"))
                if "expectedImpact" in action:
                    action["expectedImpact"] = _to_int(action.get("expectedImpact"))
                if "reversible" in action:
                    action["reversible"] = _to_bool(action.get("reversible"))
                if "parameters" in action and not isinstance(action.get("parameters"), dict):
                    action["parameters"] = {}

    def _build_options(self) -> Dict[str, Any]:
        options: Dict[str, Any] = {}
        if self.temperature is not None:
            options["temperature"] = self.temperature
        if self.top_p is not None:
            options["top_p"] = self.top_p
        if self.num_predict is not None:
            options["num_predict"] = self.num_predict
        if self.repeat_penalty is not None:
            options["repeat_penalty"] = self.repeat_penalty
        return options

    def _repair_json_with_model(self, text: str, missing_fields: Optional[List[str]]) -> str:
        missing_hint = ""
        if missing_fields:
            missing_hint = f"Missing fields: {', '.join(missing_fields)}.\n"
        repair_prompt = (
            "Fix the response so it is a single valid JSON object matching the planner schema. "
            "Output ONLY the JSON object, no extra text.\n"
            f"{missing_hint}"
            "Required top-level keys: planId, strategy, priority, summary, actions, rollbackActions, rationale, tags.\n"
            "Each action must include: type, risk, expectedImpact, reversible, parameters, rationale.\n\n"
            f"Response:\n{text}"
        )
        return self._chat(repair_prompt)
