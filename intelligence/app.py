import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Request

from intelligence.core.base import Planner, Scorer

# Load .env from project root
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_env_path)
from intelligence.core.cache import LruCache
from intelligence.core.model_registry import ModelRegistry
from intelligence.core.model_selector import ModelSelector
from intelligence.planners.custom_nn import CustomNNPlanner
from intelligence.planners.hybrid import HybridPlanner
from intelligence.planners.local_model import LocalModelPlanner
from intelligence.planners.ollama import OllamaPlanner
from intelligence.planners.remote import RemotePlanner
from intelligence.planners.rule import RulePlanner
from intelligence.planners.seq2seq import Seq2SeqPlanner
from intelligence.scorers.hybrid import HybridScorer
from intelligence.scorers.classifier import ClassifierScorer
from intelligence.scorers.local_model import LocalModelScorer
from intelligence.scorers.ollama import OllamaScorer, ollama_ok
from intelligence.scorers.rule import RuleScorer

app = FastAPI(title="Intelligence Service", version="0.1.0")
_services: Dict[str, Any] = {}
_stats: Dict[str, int] = {"score_requests": 0, "plan_requests": 0}


def _optional_float(name: str) -> Optional[float]:
    value = os.environ.get(name)
    if value in (None, ""):
        return None
    return float(value)


def _optional_int(name: str) -> Optional[int]:
    value = os.environ.get(name)
    if value in (None, ""):
        return None
    return int(value)


def _env_bool(name: str, default: bool = True) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return str(value).lower() not in ("0", "false", "no")


def _build_services() -> None:
    registry_path = os.environ.get("INTEL_MODEL_REGISTRY")
    active_profile = os.environ.get("INTEL_ACTIVE_PROFILE")
    registry: Optional[ModelSelector] = None
    if registry_path:
        path = Path(registry_path)
        if path.exists():
            registry = ModelRegistry.from_file(path, active_profile)
        else:
            print(f"[Intelligence] Model registry not found: {path}. Falling back to env config.")

    scorer_mode = os.environ.get("INTEL_SCORER_MODE", "hybrid").lower()
    local_model = os.environ.get("INTEL_LOCAL_MODEL")
    local_adapter = os.environ.get("INTEL_LOCAL_ADAPTER")
    max_new_tokens = int(os.environ.get("INTEL_LOCAL_MAX_NEW_TOKENS", "256"))
    temperature = float(os.environ.get("INTEL_LOCAL_TEMPERATURE", "0.2"))

    classifier_path = os.environ.get("INTEL_SCORER_CLASSIFIER_PATH")
    classifier_meta = os.environ.get("INTEL_SCORER_CLASSIFIER_META")
    classifier_scorer: Optional[Scorer] = None
    if scorer_mode in ("classifier", "hybrid") and classifier_path:
        classifier_scorer = ClassifierScorer(classifier_path, classifier_meta)

    local_scorer: Optional[Scorer] = None
    if scorer_mode in ("local", "hybrid") and local_model:
        local_scorer = LocalModelScorer(local_model, local_adapter, max_new_tokens, temperature)

    ollama_scorer: Optional[Scorer] = None
    if scorer_mode in ("ollama", "hybrid"):
        ollama_temperature = float(os.environ.get("INTEL_OLLAMA_TEMPERATURE", "0.1"))
        ollama_top_p = float(os.environ.get("INTEL_OLLAMA_TOP_P", "0.9"))
        ollama_num_predict = _optional_int("INTEL_OLLAMA_NUM_PREDICT")
        ollama_repeat_penalty = _optional_float("INTEL_OLLAMA_REPEAT_PENALTY")
        ollama_json_mode = _env_bool("INTEL_OLLAMA_JSON_MODE", True)
        ollama_scorer = OllamaScorer(
            base_url=os.environ.get("INTEL_OLLAMA_BASEURL", "http://localhost:11434"),
            model=os.environ.get("INTEL_OLLAMA_MODEL", "mistral"),
            timeout=float(os.environ.get("INTEL_OLLAMA_TIMEOUT", "120")),
            temperature=ollama_temperature,
            top_p=ollama_top_p,
            num_predict=ollama_num_predict,
            repeat_penalty=ollama_repeat_penalty,
            json_mode=ollama_json_mode,
        )

    fallback = RuleScorer()
    if scorer_mode == "classifier":
        scorer = classifier_scorer or fallback
    elif scorer_mode == "local":
        scorer = local_scorer or fallback
    elif scorer_mode == "ollama":
        scorer = ollama_scorer or fallback
    else:
        primary_local = classifier_scorer or local_scorer
        scorer = HybridScorer(primary_local, ollama_scorer, fallback)

    planner_mode = os.environ.get("INTEL_PLANNER_MODE", "local").lower()
    local_planner: Planner = RulePlanner()
    seq2seq_model = os.environ.get("INTEL_PLANNER_SEQ2SEQ_MODEL")
    seq2seq_max_new_tokens = int(os.environ.get("INTEL_PLANNER_SEQ2SEQ_MAX_NEW_TOKENS", "384"))
    seq2seq_num_beams = int(os.environ.get("INTEL_PLANNER_SEQ2SEQ_NUM_BEAMS", "4"))
    seq2seq_temperature = float(os.environ.get("INTEL_PLANNER_SEQ2SEQ_TEMPERATURE", "0.0"))
    seq2seq_max_source = int(os.environ.get("INTEL_PLANNER_SEQ2SEQ_MAX_SOURCE_LENGTH", "1024"))
    if planner_mode in ("seq2seq", "hybrid") and seq2seq_model:
        local_planner = Seq2SeqPlanner(
            seq2seq_model,
            max_new_tokens=seq2seq_max_new_tokens,
            num_beams=seq2seq_num_beams,
            temperature=seq2seq_temperature,
            max_source_length=seq2seq_max_source,
        )
    planner_local_model = os.environ.get("INTEL_PLANNER_LOCAL_MODEL")
    planner_local_adapter = os.environ.get("INTEL_PLANNER_LOCAL_ADAPTER")
    planner_max_new_tokens = int(os.environ.get("INTEL_PLANNER_LOCAL_MAX_NEW_TOKENS", "256"))
    planner_temperature = float(os.environ.get("INTEL_PLANNER_LOCAL_TEMPERATURE", "0.2"))
    if planner_mode in ("local", "hybrid") and planner_local_model and not isinstance(local_planner, Seq2SeqPlanner):
        local_planner = LocalModelPlanner(
            planner_local_model,
            planner_local_adapter,
            planner_max_new_tokens,
            planner_temperature,
        )
    remote_planner = None
    if planner_mode in ("remote", "hybrid"):
        remote_url = os.environ.get("INTEL_PLANNER_BASEURL")
        if remote_url:
            remote_planner = RemotePlanner(
                base_url=remote_url,
                api_key=os.environ.get("INTEL_PLANNER_API_KEY"),
                timeout=float(os.environ.get("INTEL_PLANNER_TIMEOUT", "60")),
                header=os.environ.get("INTEL_PLANNER_API_KEY_HEADER", "Authorization"),
                prefix=os.environ.get("INTEL_PLANNER_API_KEY_PREFIX", "Bearer"),
            )
    if planner_mode in ("ollama", "hybrid"):
        ollama_base = os.environ.get("INTEL_PLANNER_OLLAMA_BASEURL", "http://localhost:11434")
        ollama_model = os.environ.get("INTEL_PLANNER_OLLAMA_MODEL", "mistral")
        ollama_timeout = float(os.environ.get("INTEL_PLANNER_OLLAMA_TIMEOUT", "120"))
        planner_temperature = float(os.environ.get("INTEL_PLANNER_OLLAMA_TEMPERATURE", "0.05"))
        planner_top_p = float(os.environ.get("INTEL_PLANNER_OLLAMA_TOP_P", "0.9"))
        planner_num_predict = _optional_int("INTEL_PLANNER_OLLAMA_NUM_PREDICT")
        planner_repeat_penalty = _optional_float("INTEL_PLANNER_OLLAMA_REPEAT_PENALTY")
        planner_json_mode = _env_bool("INTEL_PLANNER_OLLAMA_JSON_MODE", True)
        remote_planner = OllamaPlanner(
            ollama_base,
            ollama_model,
            ollama_timeout,
            temperature=planner_temperature,
            top_p=planner_top_p,
            num_predict=planner_num_predict,
            repeat_penalty=planner_repeat_penalty,
            json_mode=planner_json_mode,
        )
    if planner_mode == "custom_nn":
        nn_model_path = os.environ.get("INTEL_PLANNER_NN_MODEL_PATH", "intelligence/models/planner_nn")
        planner = CustomNNPlanner(nn_model_path)
    elif planner_mode in ("remote", "ollama") and remote_planner:
        planner = remote_planner
    elif planner_mode == "seq2seq":
        planner = local_planner
    elif planner_mode == "hybrid":
        planner = HybridPlanner(local_planner, remote_planner)
    else:
        planner = local_planner

    cache_size = int(os.environ.get("INTEL_CACHE_SIZE", "256"))
    cache = LruCache(cache_size)

    _services["scorer"] = scorer
    _services["planner"] = planner
    _services["cache"] = cache
    _services["registry"] = registry


@app.on_event("startup")
async def _startup() -> None:
    _build_services()


def _cache_key(alert: Dict[str, Any], model_profile: Optional[str]) -> str:
    return json.dumps({"profile": model_profile, "alert": alert}, sort_keys=True, default=str)


def _resolve_profile(payload: Dict[str, Any], request: Request) -> Optional[str]:
    return payload.get("modelProfile") or request.headers.get("X-Intel-Profile")


@app.post("/v1/score")
async def score(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    alert = payload.get("alert") or payload or {}
    model_profile = _resolve_profile(payload, request)
    _stats["score_requests"] += 1

    cache: LruCache = _services["cache"]
    registry: Optional[ModelSelector] = _services.get("registry")
    effective_profile = registry.resolve_profile(model_profile) if registry else model_profile
    key = _cache_key(alert, effective_profile)
    cached = cache.get(key)
    if cached:
        return cached

    scorer: Scorer = registry.get_scorer(model_profile) if registry else _services["scorer"]
    result = scorer.score(alert)
    if result is None:
        result = RuleScorer().score(alert) or {
            "severity": 40,
            "confidence": 0.5,
            "hypothesis": "fallback",
            "evidence": ["fallback"],
        }

    cache.set(key, result)
    return result


@app.post("/v1/score/batch")
async def score_batch(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    items = payload.get("alerts") or []
    results = []
    model_profile = _resolve_profile(payload, request)
    registry: Optional[ModelSelector] = _services.get("registry")
    effective_profile = registry.resolve_profile(model_profile) if registry else model_profile
    scorer: Scorer = registry.get_scorer(model_profile) if registry else _services["scorer"]
    cache: LruCache = _services["cache"]

    for alert in items:
        _stats["score_requests"] += 1
        key = _cache_key(alert, effective_profile)
        cached = cache.get(key)
        if cached:
            results.append(cached)
            continue
        result = scorer.score(alert)
        if result is None:
            result = RuleScorer().score(alert) or {
                "severity": 40,
                "confidence": 0.5,
                "hypothesis": "fallback",
                "evidence": ["fallback"],
            }
        cache.set(key, result)
        results.append(result)

    return {"results": results}


@app.post("/v1/plan")
async def plan(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    alert = payload.get("alert") or {}
    assessment = payload.get("assessment") or {}
    model_profile = _resolve_profile(payload, request)
    _stats["plan_requests"] += 1
    registry: Optional[ModelSelector] = _services.get("registry")
    planner: Planner = registry.get_planner(model_profile) if registry else _services["planner"]
    try:
        return {"plan": planner.plan(alert, assessment)}
    except Exception:
        return {"plan": RulePlanner().plan(alert, assessment)}


@app.get("/v1/models")
async def list_models() -> Dict[str, Any]:
    registry: Optional[ModelSelector] = _services.get("registry")
    if not registry:
        return {"active": None, "profiles": []}
    return {"active": registry.active_profile, "profiles": registry.list_profiles()}


@app.get("/health")
async def health() -> Dict[str, Any]:
    scorer = _services.get("scorer")
    planner = _services.get("planner")
    cache: LruCache = _services.get("cache")
    registry: Optional[ModelSelector] = _services.get("registry")

    if scorer.__class__.__name__ in ("LocalModelScorer", "ClassifierScorer"):
        local_loaded = True
    elif scorer.__class__.__name__ == "HybridScorer":
        local_loaded = getattr(scorer, "local_scorer", None) is not None
    elif scorer.__class__.__name__ == "CalibratedScorer":
        local_loaded = getattr(scorer, "classifier", None) is not None
    else:
        local_loaded = False

    base_url = os.environ.get("INTEL_OLLAMA_BASEURL", "http://localhost:11434")
    ollama_status = False
    if scorer.__class__.__name__ in ("OllamaScorer", "HybridScorer"):
        ollama_status = ollama_ok(base_url)
    elif scorer.__class__.__name__ == "CalibratedScorer":
        explainer = getattr(scorer, "explainer", None)
        if explainer and explainer.__class__.__name__ == "OllamaScorer":
            ollama_status = ollama_ok(base_url)

    return {
        "ok": True,
        "scorer": scorer.__class__.__name__ if scorer else None,
        "planner": planner.__class__.__name__ if planner else None,
        "model_registry": bool(registry),
        "active_profile": registry.active_profile if registry else None,
        "profiles": registry.list_profiles() if registry else [],
        "local_model_loaded": local_loaded,
        "ollama_ok": ollama_status,
        "score_requests": _stats["score_requests"],
        "plan_requests": _stats["plan_requests"],
        "cache_size": cache.size() if cache else 0,
        "cache_items": cache.count() if cache else 0,
    }


def main() -> None:
    import uvicorn

    host = os.environ.get("INTEL_HOST", "0.0.0.0")
    port = int(os.environ.get("INTEL_PORT", "8080"))
    uvicorn.run("intelligence.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
