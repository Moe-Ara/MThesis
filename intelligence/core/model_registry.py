import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from intelligence.core.base import Planner, Scorer
from intelligence.planners.custom_nn import CustomNNPlanner
from intelligence.planners.hybrid import HybridPlanner
from intelligence.planners.local_model import LocalModelPlanner
from intelligence.planners.ollama import OllamaPlanner
from intelligence.planners.remote import RemotePlanner
from intelligence.planners.rule import RulePlanner
from intelligence.planners.seq2seq import Seq2SeqPlanner
from intelligence.scorers.calibrated import CalibratedScorer
from intelligence.scorers.classifier import ClassifierScorer
from intelligence.scorers.hybrid import HybridScorer
from intelligence.scorers.local_model import LocalModelScorer
from intelligence.scorers.ollama import OllamaScorer
from intelligence.scorers.rule import RuleScorer


@dataclass
class ModelProfile:
    name: str
    scorer: Dict[str, Any]
    planner: Dict[str, Any]


class ModelRegistry:
    def __init__(
        self,
        profiles: Dict[str, ModelProfile],
        active_profile: Optional[str] = None,
        base_dir: Optional[Path] = None,
    ):
        self._profiles = profiles
        self._active_profile = active_profile
        self._base_dir = base_dir or Path.cwd()
        self._scorers: Dict[str, Scorer] = {}
        self._planners: Dict[str, Planner] = {}

    @property
    def active_profile(self) -> Optional[str]:
        return self._active_profile

    def list_profiles(self) -> List[str]:
        return list(self._profiles.keys())

    def resolve_profile(self, requested: Optional[str]) -> Optional[str]:
        if requested and requested in self._profiles:
            return requested
        if self._active_profile and self._active_profile in self._profiles:
            return self._active_profile
        return next(iter(self._profiles.keys()), None)

    def get_scorer(self, requested: Optional[str]) -> Scorer:
        profile = self.resolve_profile(requested)
        if not profile:
            return RuleScorer()
        if profile not in self._scorers:
            self._scorers[profile] = self._build_scorer(self._profiles[profile].scorer)
        return self._scorers[profile]

    def get_planner(self, requested: Optional[str]) -> Planner:
        profile = self.resolve_profile(requested)
        if not profile:
            return RulePlanner()
        if profile not in self._planners:
            self._planners[profile] = self._build_planner(self._profiles[profile].planner)
        return self._planners[profile]

    @classmethod
    def from_file(cls, path: Path, active_override: Optional[str] = None) -> "ModelRegistry":
        data = json.loads(path.read_text(encoding="utf-8"))
        profiles: Dict[str, ModelProfile] = {}
        raw_profiles = data.get("profiles") or {}
        for name, cfg in raw_profiles.items():
            profiles[name] = ModelProfile(
                name=name,
                scorer=cfg.get("scorer") or {},
                planner=cfg.get("planner") or {},
            )
        active = active_override or data.get("active")
        return cls(profiles, active, base_dir=path.parent)

    def _resolve_path(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        path = Path(value)
        if path.is_absolute():
            return str(path)
        return str(self._base_dir / path)

    def _build_scorer(self, cfg: Dict[str, Any]) -> Scorer:
        mode = str(cfg.get("type") or "rule").lower()

        if mode == "rule":
            return RuleScorer()
        if mode == "calibrated":
            classifier_cfg = cfg.get("classifier") or {}
            explainer_cfg = cfg.get("explainer") or cfg.get("ollama") or {}
            classifier = self._build_scorer(classifier_cfg) if classifier_cfg else None
            explainer = self._build_scorer(explainer_cfg) if explainer_cfg else None
            confidence_floor = float(cfg.get("confidence_floor", 0.15))
            confidence_ceiling = float(cfg.get("confidence_ceiling", 0.99))
            return CalibratedScorer(classifier, explainer, confidence_floor, confidence_ceiling)
        if mode == "classifier":
            model_path = self._resolve_path(cfg.get("model_path") or cfg.get("model"))
            meta_path = self._resolve_path(cfg.get("meta_path"))
            if not model_path:
                raise ValueError("Classifier scorer requires model_path.")
            return ClassifierScorer(model_path, meta_path)
        if mode == "local":
            model = cfg.get("model")
            if not model:
                raise ValueError("Local scorer requires model.")
            adapter = self._resolve_path(cfg.get("adapter"))
            max_new_tokens = int(cfg.get("max_new_tokens", 256))
            temperature = float(cfg.get("temperature", 0.2))
            return LocalModelScorer(model, adapter, max_new_tokens, temperature)
        if mode == "ollama":
            base_url = cfg.get("base_url") or os.environ.get("INTEL_OLLAMA_BASEURL", "http://localhost:11434")
            model = cfg.get("model") or os.environ.get("INTEL_OLLAMA_MODEL", "mistral")
            timeout = float(cfg.get("timeout", os.environ.get("INTEL_OLLAMA_TIMEOUT", "120")))
            temperature = float(cfg.get("temperature", os.environ.get("INTEL_OLLAMA_TEMPERATURE", "0.1")))
            top_p = float(cfg.get("top_p", os.environ.get("INTEL_OLLAMA_TOP_P", "0.9")))
            num_predict = cfg.get("num_predict", os.environ.get("INTEL_OLLAMA_NUM_PREDICT"))
            repeat_penalty = cfg.get("repeat_penalty", os.environ.get("INTEL_OLLAMA_REPEAT_PENALTY"))
            json_mode = str(cfg.get("json_mode", os.environ.get("INTEL_OLLAMA_JSON_MODE", "true"))).lower()
            num_predict_val = int(num_predict) if num_predict not in (None, "") else None
            repeat_penalty_val = float(repeat_penalty) if repeat_penalty not in (None, "") else None
            return OllamaScorer(
                base_url,
                model,
                timeout,
                temperature=temperature,
                top_p=top_p,
                num_predict=num_predict_val,
                repeat_penalty=repeat_penalty_val,
                json_mode=json_mode != "false",
            )
        if mode == "hybrid":
            primary_cfg = cfg.get("primary") or cfg.get("local") or {}
            secondary_cfg = cfg.get("secondary") or cfg.get("ollama") or {}
            fallback_cfg = cfg.get("fallback") or {"type": "rule"}
            primary = self._build_scorer(primary_cfg) if primary_cfg else None
            secondary = self._build_scorer(secondary_cfg) if secondary_cfg else None
            fallback = self._build_scorer(fallback_cfg)
            return HybridScorer(primary, secondary, fallback)

        raise ValueError(f"Unknown scorer type: {mode}")

    def _build_planner(self, cfg: Dict[str, Any]) -> Planner:
        mode = str(cfg.get("type") or "rule").lower()

        if mode == "rule":
            return RulePlanner()
        if mode == "custom_nn":
            model_path = self._resolve_path(cfg.get("model_path") or cfg.get("model"))
            if not model_path:
                raise ValueError("Custom NN planner requires model_path.")
            action_threshold = float(cfg.get("action_threshold", 0.5))
            return CustomNNPlanner(model_path, action_threshold=action_threshold)
        if mode == "seq2seq":
            model = self._resolve_path(cfg.get("model_path") or cfg.get("model"))
            if not model:
                raise ValueError("Seq2Seq planner requires model_path.")
            max_new_tokens = int(cfg.get("max_new_tokens", 384))
            num_beams = int(cfg.get("num_beams", 4))
            temperature = float(cfg.get("temperature", 0.0))
            max_source_length = int(cfg.get("max_source_length", 1024))
            return Seq2SeqPlanner(
                model,
                max_new_tokens=max_new_tokens,
                num_beams=num_beams,
                temperature=temperature,
                max_source_length=max_source_length,
            )
        if mode == "local":
            model = cfg.get("model")
            if not model:
                raise ValueError("Local planner requires model.")
            adapter = self._resolve_path(cfg.get("adapter"))
            max_new_tokens = int(cfg.get("max_new_tokens", 256))
            temperature = float(cfg.get("temperature", 0.2))
            return LocalModelPlanner(model, adapter, max_new_tokens, temperature)
        if mode == "ollama":
            base_url = cfg.get("base_url") or os.environ.get("INTEL_PLANNER_OLLAMA_BASEURL", "http://localhost:11434")
            model = cfg.get("model") or os.environ.get("INTEL_PLANNER_OLLAMA_MODEL", "mistral")
            timeout = float(cfg.get("timeout", os.environ.get("INTEL_PLANNER_OLLAMA_TIMEOUT", "120")))
            temperature = float(cfg.get("temperature", os.environ.get("INTEL_PLANNER_OLLAMA_TEMPERATURE", "0.05")))
            top_p = float(cfg.get("top_p", os.environ.get("INTEL_PLANNER_OLLAMA_TOP_P", "0.9")))
            num_predict = cfg.get("num_predict", os.environ.get("INTEL_PLANNER_OLLAMA_NUM_PREDICT"))
            repeat_penalty = cfg.get("repeat_penalty", os.environ.get("INTEL_PLANNER_OLLAMA_REPEAT_PENALTY"))
            json_mode = str(cfg.get("json_mode", os.environ.get("INTEL_PLANNER_OLLAMA_JSON_MODE", "true"))).lower()
            num_predict_val = int(num_predict) if num_predict not in (None, "") else None
            repeat_penalty_val = float(repeat_penalty) if repeat_penalty not in (None, "") else None
            return OllamaPlanner(
                base_url,
                model,
                timeout,
                temperature=temperature,
                top_p=top_p,
                num_predict=num_predict_val,
                repeat_penalty=repeat_penalty_val,
                json_mode=json_mode != "false",
            )
        if mode == "remote":
            base_url = cfg.get("base_url")
            if not base_url:
                raise ValueError("Remote planner requires base_url.")
            return RemotePlanner(
                base_url=base_url,
                api_key=cfg.get("api_key"),
                timeout=float(cfg.get("timeout", 60)),
                header=cfg.get("header", "Authorization"),
                prefix=cfg.get("prefix", "Bearer"),
            )
        if mode == "hybrid":
            local_cfg = cfg.get("local") or {"type": "rule"}
            remote_cfg = cfg.get("remote") or cfg.get("ollama")
            local_planner = self._build_planner(local_cfg)
            remote_planner = self._build_planner(remote_cfg) if remote_cfg else None
            return HybridPlanner(local_planner, remote_planner)

        raise ValueError(f"Unknown planner type: {mode}")
