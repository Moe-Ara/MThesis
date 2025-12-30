"""Agent that uses the knowledge base to craft executable scripts."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from thesis.agents.base import Agent
from thesis.blackboard.core import Blackboard
from thesis.behavior import ActionNode, BehaviorTree, SequenceNode, SelectorNode
from thesis.decision.tree import DecisionNode, DecisionTree
from thesis.knowledge.core import KnowledgeBase, KnowledgeEntry


class ScriptAgent(Agent):
    """Creates executable scripts by combining knowledge base instructions."""

    name = "script"

    def __init__(
        self,
        knowledge_base: KnowledgeBase,
        board: Optional[Blackboard] = None,
        default_language: str = "bash",
    ) -> None:
        self.knowledge_base = knowledge_base
        self.default_language = default_language
        self.board = board
        self.behavior_tree = self._build_behavior_tree()
        self.decision_tree = self._build_decision_tree()
        self._entries: List[KnowledgeEntry] = []
        self._commands: List[str] = []
        self._script_text: str = ""

        if self.board:
            self.board.subscribe("rule_generated", self._on_rule_generated)

    def run(
        self,
        *,
        topic: str,
        language: Optional[str] = None,
        script_name: str = "automation-script",
        extra_commands: Optional[Sequence[str]] = None,
        threat_event: Optional[Dict[str, Any]] = None,
        execute: bool = False,
    ) -> Dict[str, Any]:
        language = language or self.default_language
        self._entries = self.knowledge_base.search(topic)
        commands: List[str] = []
        for entry in self._entries:
            commands.extend(entry.commands)
        if extra_commands:
            commands.extend(extra_commands)
        self._commands = [cmd.strip() for cmd in commands if cmd.strip()]

        if self.board:
            self.board.set("topic", topic)
            self.board.set("language", language)
            self.board.set("threat_event", threat_event or {})

        context = {
            "board": self.board,
            "topic": topic,
            "language": language,
            "script_name": script_name,
            "execute": execute,
            "threat_event": threat_event,
        }
        self.behavior_tree.tick(context)

        result = {
            "script_text": self._script_text,
            "language": language,
            "topic": topic,
            "script_name": script_name,
            "commands": self._commands,
            "entries": [entry.title for entry in self._entries],
        }
        if self.board:
            self.board.set("last_script", result)
            self.board.publish("script_generated", result)
        return result

    def _build_script(
        self,
        *,
        language: str,
        topic: str,
        script_name: str,
        commands: List[str],
        entries: Sequence[KnowledgeEntry],
    ) -> str:
        shebang_map = {
            "bash": "#!/usr/bin/env bash",
            "sh": "#!/usr/bin/env sh",
            "powershell": "#!/usr/bin/env pwsh",
        }
        shebang = shebang_map.get(language.lower(), f"#!/usr/bin/env {language}")
        lines = [shebang, f"# Script: {script_name}", f"# Topic: {topic}", ""]
        if entries:
            lines.append("# Knowledge base entries:")
            for entry in entries:
                summary = entry.summary or entry.title
                lines.append(f"# - {entry.title}: {summary}")
            lines.append("")
        if commands:
            lines.append("# Execution steps")
            lines.extend(commands)
        else:
            lines.append("# TODO: populate script commands manually.")
        return "\n".join(lines).rstrip() + "\n"

    def _build_behavior_tree(self) -> BehaviorTree:
        root = SequenceNode("script-main")
        root.add_child(ActionNode("prepare", self._prepare_context))
        selector = SelectorNode("threat-or-knowledge")
        selector.add_child(ActionNode("handle-threat", self._handle_threat))
        selector.add_child(ActionNode("include-knowledge", self._apply_knowledge))
        selector.add_child(ActionNode("fallback", self._apply_fallback))
        root.add_child(selector)
        root.add_child(ActionNode("maybe-execute", self._maybe_execute))
        return BehaviorTree(root)

    def _build_decision_tree(self) -> DecisionTree:
        root = DecisionNode("default-language", action="bash")
        high = DecisionNode(
            "python",
            condition=lambda ctx: ctx.get("threat_severity", 0) >= 7,
            action="python",
        )
        root.add_child(high)
        return DecisionTree(root)

    def _prepare_context(self, context: Dict[str, Any]) -> bool:
        context["has_knowledge"] = bool(self._entries)
        return True

    def _apply_knowledge(self, context: Dict[str, Any]) -> bool:
        if not context.get("has_knowledge"):
            return False
        self._script_text = self._build_script(
            language=context["language"],
            topic=context["topic"],
            script_name=context["script_name"],
            commands=self._commands,
            entries=self._entries,
        )
        return True

    def _apply_fallback(self, context: Dict[str, Any]) -> bool:
        placeholder_commands: List[str] = []
        if self.board and (rule := self.board.get("last_rule_result")):
            placeholder_commands.append(
                f'echo "Referencing previous rule: {rule.get("rule_xml")[:80]}"'
            )
        self._script_text = self._build_script(
            language=context["language"],
            topic=context["topic"],
            script_name=context["script_name"],
            commands=placeholder_commands,
            entries=self._entries,
        )
        return True

    def _handle_threat(self, context: Dict[str, Any]) -> bool:
        threat = context.get("threat_event") or {}
        if not threat and not (self.board and self.board.get("threat_event")):
            return False
        severity = threat.get("severity", 0)
        language = self.decision_tree.decide(
            {"threat_severity": severity}
        )  # type: ignore[arg-type]
        commands = list(threat.get("commands", []))
        if not commands:
            desc = threat.get("description", "unknown threat")
            commands = [f'echo "Handling threat: {desc}"']
        self._commands = [cmd.strip() for cmd in commands if cmd.strip()]
        self._script_text = self._build_script(
            language=language,
            topic=context["topic"],
            script_name=context["script_name"],
            commands=self._commands,
            entries=self._entries,
        )
        context["language"] = language
        if self.board:
            self.board.set("last_threat_script", language)
        return True

    def _maybe_execute(self, context: Dict[str, Any]) -> bool:
        execute = context.get("execute")
        if not execute or not self._script_text:
            return True
        executed = self._execute_script(self._script_text, context["language"])
        if self.board:
            self.board.set("last_execution_result", executed)
        return True

    def _execute_script(self, script_text: str, language: str) -> bool:
        file_ext = ".py" if language == "python" else ".sh"
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext, mode="w", encoding="utf-8") as tmp:
            tmp.write(script_text)
            tmp_path = tmp.name
        os.chmod(tmp_path, 0o755)
        try:
            if language == "python":
                interpreter = sys.executable
                cmd = [interpreter, tmp_path]
            else:
                if os.name == "nt":
                    interpreter = "cmd.exe"
                    cmd = [interpreter, "/c", tmp_path]
                else:
                    interpreter = "/bin/bash"
                    cmd = [interpreter, tmp_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            if self.board:
                self.board.set("execution_stdout", result.stdout)
                self.board.set("execution_stderr", result.stderr)
            return result.returncode == 0
        finally:
            os.remove(tmp_path)

    def _on_rule_generated(self, topic: str, payload: Any) -> None:
        if not self.board:
            return
        self.board.set("last_rule_context", payload)
