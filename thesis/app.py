"""Command-line entry point that orchestrates dataset and rule agents."""

import argparse
import json
from pathlib import Path
from typing import List, Optional

from thesis.agents import DatasetAgent, RuleAgent, ScriptAgent
from thesis.blackboard.core import Blackboard
from thesis.dataset.builder import CsvDatasetBuilder
from thesis.llm.client import OllamaLlmClient
from thesis.llm.local_client import LocalTransformerClient
from thesis.knowledge.core import KnowledgeBase


class ThesisApp:
    """Entrypoint object that wires together dataset and rule agents."""

    def __init__(self) -> None:
        self._parser = self._build_parser()
        self.blackboard = Blackboard()

    def run(self, argv: Optional[List[str]] = None) -> None:
        """Parse CLI arguments, delegate to the requested agent, and emit the results."""
        args = self._parser.parse_args(argv)
        if args.command == "dataset":
            self._run_dataset(args)
        elif args.command == "rule":
            self._run_rule(args)
        elif args.command == "script":
            self._run_script(args)

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="thesis")
        subparsers = parser.add_subparsers(dest="command", required=True)

        dataset_parser = subparsers.add_parser(
            "dataset", help="Build or update a CSV dataset from JSON logs."
        )
        dataset_parser.add_argument(
            "--database",
            type=Path,
            required=True,
            help="Path to the CSV dataset to manage.",
        )
        dataset_parser.add_argument(
            "--fields",
            nargs="+",
            required=True,
            help="Columns that should appear in the CSV file.",
        )
        dataset_parser.add_argument(
            "--unique-fields",
            nargs="+",
            help="Fields used to detect duplicates (defaults to --fields order).",
        )
        dataset_parser.add_argument(
            "--logs",
            type=Path,
            help="JSON file containing one event or a list of events.",
        )
        dataset_parser.add_argument(
            "--logs-dir",
            type=Path,
            help="Directory containing JSON log files to ingest alongside --logs.",
        )
        dataset_parser.add_argument(
            "--dedup",
            action="store_true",
            help="Rewrite the CSV to remove duplicates after appending.",
        )

        rule_parser = subparsers.add_parser(
            "rule", help="Generate Wazuh rule XML using Ollama."
        )
        script_parser = subparsers.add_parser(
            "script", help="Generate executable scripts from the knowledge base."
        )
        rule_parser.add_argument(
            "--detection-goal",
            required=True,
            help="High-level description of what the rule should detect.",
        )
        rule_parser.add_argument(
            "--existing-rules",
            type=Path,
            help="Path to the existing Wazuh rules XML file.",
        )
        rule_parser.add_argument(
            "--logs",
            type=Path,
            help="Path to a JSON file containing sample logs.",
        )
        rule_parser.add_argument(
            "--client",
            choices=["ollama", "local"],
            default="ollama",
            help="Which LLM client to use when generating rules.",
        )
        rule_parser.add_argument(
            "--model",
            default="mistral",
            help="Name of the Ollama model to use (client=ollama).",
        )
        rule_parser.add_argument(
            "--base-url",
            default="http://localhost:11434",
            help="Base URL for the Ollama API (client=ollama).",
        )
        rule_parser.add_argument(
            "--local-adapter",
            type=Path,
            default=Path("wazuh-specialized"),
            help="Path to the LoRA adapter or local tokenizer (client=local).",
        )
        rule_parser.add_argument(
            "--local-base-model",
            default="Qwen/Qwen2.5-3B",
            help="Hugging Face base model when using the local client.",
        )
        rule_parser.add_argument(
            "--local-max-new-tokens",
            type=int,
            default=512,
            help="Generation budget when running the local client.",
        )
        rule_parser.add_argument(
            "--local-temperature",
            type=float,
            default=0.2,
            help="Sampling temperature for the local model.",
        )
        rule_parser.add_argument(
            "--rule-output",
            type=Path,
            default=Path("generated_rules.xml"),
            help="File that receives the generated rule XML (appended by default).",
        )
        rule_parser.add_argument(
            "--overwrite",
            action="store_true",
            help="Overwrite `--rule-output` instead of appending.",
        )
        rule_parser.add_argument(
            "--system-prompt-file",
            type=Path,
            help="Custom system prompt text to replace the default Wazuh assistant prompt.",
        )
        rule_parser.add_argument(
            "--force",
            action="store_true",
            help="Force regeneration even if cached data exists on the blackboard.",
        )

        script_parser.add_argument(
            "--topic",
            required=True,
            help="Topic that guides the script generation.",
        )
        script_parser.add_argument(
            "--language",
            default="bash",
            help="Target shell/language for the generated script.",
        )
        script_parser.add_argument(
            "--script-name",
            default="automation-script",
            help="Friendly name used in the generated header comment.",
        )
        script_parser.add_argument(
            "--knowledge-base",
            type=Path,
            default=Path("data/knowledge_base.jsonl"),
            help="Path to the newline-delimited knowledge base.",
        )
        script_parser.add_argument(
            "--script-output",
            type=Path,
            default=Path("scripts/generated_script.sh"),
            help="Location to persist the generated script.",
        )
        script_parser.add_argument(
            "--overwrite",
            action="store_true",
            help="Overwrite the script output instead of appending.",
        )
        script_parser.add_argument(
            "--extra-command",
            action="append",
            help="Additional command(s) to append to the generated script.",
        )
        script_parser.add_argument(
            "--threat-level",
            type=int,
            help="Threat severity (0-10) that should influence the response.",
        )
        script_parser.add_argument(
            "--threat-description",
            help="Natural language description of the current threat.",
        )
        script_parser.add_argument(
            "--threat-command",
            action="append",
            help="Command(s) to execute when handling a threat.",
        )
        script_parser.add_argument(
            "--execute",
            action="store_true",
            help="Execute the generated script immediately.",
        )

        return parser

    def _run_dataset(self, args: argparse.Namespace) -> None:
        log_paths: List[Path] = []
        if args.logs:
            if not args.logs.exists():
                raise SystemExit(f"Log file {args.logs} does not exist.")
            log_paths.append(args.logs)
        if args.logs_dir:
            if not args.logs_dir.is_dir():
                raise SystemExit(
                    f"--logs-dir must be a directory, got {args.logs_dir!r}."
                )
            log_paths.extend(sorted(args.logs_dir.glob("*.json")))

        if not log_paths:
            raise SystemExit("At least one log file or --logs-dir is required.")

        builder = CsvDatasetBuilder(
            path=args.database,
            fieldnames=args.fields,
            unique_fields=args.unique_fields,
        )
        agent = DatasetAgent(builder, board=self.blackboard)
        result = agent.run(log_paths=log_paths, dedup=args.dedup)

        output = {
            "operation": "dataset_ingest",
            "database": str(args.database),
            "fields": args.fields,
            "unique_fields": args.unique_fields or args.fields,
            **result,
        }
        print(json.dumps(output, indent=2))

    def _run_rule(self, args: argparse.Namespace) -> None:
        existing_rules = None
        if args.existing_rules:
            if not args.existing_rules.exists():
                raise SystemExit(
                    f"Existing rules file {args.existing_rules} does not exist."
                )
            existing_rules = args.existing_rules.read_text(encoding="utf-8")

        logs = []
        if args.logs:
            if not args.logs.exists():
                raise SystemExit(f"Log file {args.logs} does not exist.")
            logs = RuleAgent.load_logs_from_file(args.logs)

        prompt_override = None
        if args.system_prompt_file:
            if not args.system_prompt_file.exists():
                raise SystemExit(
                    f"System prompt file {args.system_prompt_file} does not exist."
                )
            prompt_override = args.system_prompt_file.read_text(encoding="utf-8")

        if args.client == "ollama":
            client = OllamaLlmClient(model=args.model, base_url=args.base_url)
        else:
            client = LocalTransformerClient(
                adapter_path=args.local_adapter,
                base_model=args.local_base_model,
                max_new_tokens=args.local_max_new_tokens,
                temperature=args.local_temperature,
            )
        agent_kwargs = {"llm_client": client, "board": self.blackboard}
        if prompt_override is not None:
            agent_kwargs["system_prompt"] = prompt_override
        rule_agent = RuleAgent(**agent_kwargs)

        result = rule_agent.run(
            detection_goal=args.detection_goal,
            example_events=logs,
            existing_rules_xml=existing_rules,
            existing_logs=logs,
            force_generate=args.force,
        )
        print(json.dumps(result, indent=2))

        rule_text = result.get("rule_xml", "").strip()
        if args.rule_output and rule_text:
            self._write_rule_output(args.rule_output, rule_text, args.overwrite)

    def _run_script(self, args: argparse.Namespace) -> None:
        if not args.knowledge_base.exists():
            raise SystemExit(
                f"Knowledge base file {args.knowledge_base} does not exist."
            )
        knowledge = KnowledgeBase.load(args.knowledge_base)
        agent = ScriptAgent(knowledge, board=self.blackboard, default_language=args.language)
        threat_event = None
        if args.threat_level is not None or args.threat_description or args.threat_command:
            threat_event = {
                "severity": args.threat_level or 0,
                "description": args.threat_description,
                "commands": args.threat_command or [],
            }
        result = agent.run(
            topic=args.topic,
            language=args.language,
            script_name=args.script_name,
            extra_commands=args.extra_command or [],
            threat_event=threat_event,
            execute=args.execute,
        )
        print(json.dumps(result, indent=2))

        if args.script_output and result.get("script_text"):
            self._write_script_output(args.script_output, result["script_text"], args.overwrite)

    def _write_rule_output(self, path: Path, text: str, overwrite: bool) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if overwrite:
            path.write_text(f"{text}\n", encoding="utf-8")
            return

        existing = ""
        if path.exists():
            existing = path.read_text(encoding="utf-8")
            if existing and not existing.endswith("\n"):
                existing += "\n"
        path.write_text(f"{existing}{text}\n", encoding="utf-8")

    def _write_script_output(self, path: Path, text: str, overwrite: bool) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if overwrite:
            path.write_text(text, encoding="utf-8")
            return

        existing = ""
        if path.exists():
            existing = path.read_text(encoding="utf-8")
            if existing and not existing.endswith("\n"):
                existing += "\n"
        path.write_text(f"{existing}{text}", encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> None:
    ThesisApp().run(argv)
