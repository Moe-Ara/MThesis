"""Agent that summarizes logs and asks Ollama to emit Wazuh-style XML rules."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from thesis.agents.base import Agent
from thesis.blackboard.core import Blackboard
from thesis.behavior import ActionNode, BehaviorTree, SequenceNode, SelectorNode
from thesis.decision.tree import DecisionTree, DecisionNode
from thesis.llm.base import LlmClient

WAZUH_RULE_SYSTEM_PROMPT = """
You are a Wazuh detection engineering assistant.

Goal:
- Help create efficient, precise Wazuh rules based on a detection goal, any existing rules,
  and sample log events.
- Output ready-to-use Wazuh rule XML plus short explanations.

Wazuh basics:
- Rules are defined inside <group> and <rule> tags.
- Each <rule> has at least:
  - id (integer > 100000 for custom rules),
  - level (severity 0-15),
  - description text,
  - optional conditions like: <if_group>, <if_sid>, <match>, <field>, <frequency>, <timeframe>, etc.
- Only use valid Wazuh fields and tags.
- Prefer specificity over noise: narrow the rule to likely malicious patterns.

Workflow:
1. Read "detection_goal", "existing_rules", and "example_events" (or "existing_logs") as they are provided.
2. Decide which Wazuh log group(s) and conditions are relevant.
3. Generate ONE primary Wazuh rule as XML:
   - Use a custom rule id in the range 100500-100999.
   - Provide a meaningful <description>.
   - Add conditions that are as specific as possible.
4. Use the provided rules and logs to suggest improvements, either by refining an existing rule
   or proposing a complementary detection.
5. If useful, you may add an aggregation rule that correlates repeated events using <frequency>
   and <timeframe>.

Output format:
Respond ONLY with a JSON object with the following structure:

{
  "rule_xml": "<group name=\\"...\\"><rule id=\\"...\\"> ... </rule></group>",
  "explanation": "Human-readable explanation of what the rule detects.",
  "tuning_suggestions": [
    "Suggestion 1 ...",
    "Suggestion 2 ..."
  ],
  "test_plan": [
    "Step 1 ...",
    "Step 2 ..."
  ]
}

Do not include any text outside this JSON object.
"""


class RuleAgent(Agent):
    """Handles payload construction and dispatch to the Ollama client."""

    name = "rule"

    def __init__(
        self,
        llm_client: LlmClient,
        board: Blackboard,
        system_prompt: str = WAZUH_RULE_SYSTEM_PROMPT,
        behavior_tree: Optional[BehaviorTree] = None,
    ) -> None:
        self._llm = llm_client
        self.system_prompt = system_prompt
        self.board = board
        self.behavior_tree = behavior_tree or self._build_behavior_tree()

    def _build_behavior_tree(self) -> BehaviorTree:
        root = SequenceNode("rule-main")
        root.add_child(ActionNode("ensure-goal", self._ensure_goal))
        selector = SelectorNode("reuse-or-generate")
        selector.add_child(ActionNode("reuse-last-result", self._reuse_existing))
        selector.add_child(ActionNode("generate", self._generate_rule))
        root.add_child(selector)
        return BehaviorTree(root)

    def create_rule(
        self,
        detection_goal: str,
        example_events: Optional[List[Dict[str, Any]]] = None,
        existing_rules_xml: Optional[str] = None,
        existing_logs: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "detection_goal": detection_goal,
            "siem": "wazuh",
            "example_events": example_events or [],
        }

        if existing_rules_xml:
            payload["existing_rules"] = existing_rules_xml
        if existing_logs:
            payload["existing_logs"] = existing_logs

        return self._llm.generate(self.system_prompt, payload)

    def run(
        self,
        *,
        detection_goal: str,
        example_events: Optional[List[Dict[str, Any]]] = None,
        existing_rules_xml: Optional[str] = None,
        existing_logs: Optional[List[Dict[str, Any]]] = None,
        force_generate: bool = False,
    ) -> Dict[str, Any]:
        """Execute the agent’s behavior tree with the provided context."""

        self.board.set("detection_goal", detection_goal)
        self.board.set("existing_rules", existing_rules_xml)
        self.board.set("example_events", example_events or [])
        self.board.set("existing_logs", existing_logs or [])
        self.board.set("force_generate", force_generate)

        context = {
            "board": self.board,
            "decision": DecisionTree(
                DecisionNode("root")  # placeholder for future expansions
            ),
        }

        self.behavior_tree.tick(context)
        return self.board.get("last_rule_result") or {}

    def create_rule(
        self,
        detection_goal: str,
        example_events: Optional[List[Dict[str, Any]]] = None,
        existing_rules_xml: Optional[str] = None,
        existing_logs: Optional[List[Dict[str, Any]]] = None,
        force_generate: bool = False,
    ) -> Dict[str, Any]:
        return self.run(
            detection_goal=detection_goal,
            example_events=example_events,
            existing_rules_xml=existing_rules_xml,
            existing_logs=existing_logs,
            force_generate=force_generate,
        )

    def _ensure_goal(self, context: Dict[str, Any]) -> bool:
        board = context["board"]
        return bool(board.get("detection_goal"))

    def _reuse_existing(self, context: Dict[str, Any]) -> bool:
        board = context["board"]
        if board.get("force_generate"):
            return False
        return bool(board.get("last_rule_result"))

    def _generate_rule(self, context: Dict[str, Any]) -> bool:
        board = context["board"]
        payload = {
            "detection_goal": board.get("detection_goal"),
            "siem": "wazuh",
            "example_events": board.get("example_events"),
            "existing_rules": board.get("existing_rules"),
            "existing_logs": board.get("existing_logs"),
        }
        try:
            result = self._llm.generate(self.system_prompt, payload)
        except Exception:
            return False
        board.set("last_rule_result", result)
        board.publish("rule_generated", result)
        return True

    @staticmethod
    def load_logs_from_file(path: Path) -> List[Dict[str, Any]]:
        """Load either a single JSON object or an array of objects for prompts."""
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            return []

        data = json.loads(raw)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        raise ValueError("Log file must contain a JSON object or array.")
