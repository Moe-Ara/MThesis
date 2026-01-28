import json
import os
from typing import Any, Dict, Optional

from fastapi import FastAPI

from intelligence.core.base import Planner, Scorer
from intelligence.core.cache import LruCache
from intelligence.core.utils import extract_json
from intelligence.planners.hybrid import HybridPlanner
from intelligence.planners.local_model import LocalModelPlanner
from intelligence.planners.ollama import OllamaPlanner
from intelligence.planners.remote import RemotePlanner
from intelligence.planners.rule import RulePlanner
from intelligence.scorers.hybrid import HybridScorer
from intelligence.scorers.local_model import LocalModelScorer
from intelligence.scorers.ollama import OllamaScorer, ollama_ok
from intelligence.scorers.rule import RuleScorer

app = FastAPI(title="Intelligence Service", version="0.1.0")
_services: Dict[str, Any] = {}
_stats: Dict[str, int] = {"score_requests": 0, "plan_requests": 0}


def _build_services() -> None:
    scorer_mode = os.environ.get("INTEL_SCORER_MODE", "hybrid").lower()
    local_model = os.environ.get("INTEL_LOCAL_MODEL")
    local_adapter = os.environ.get("INTEL_LOCAL_ADAPTER")
    max_new_tokens = int(os.environ.get("INTEL_LOCAL_MAX_NEW_TOKENS", "256"))
    temperature = float(os.environ.get("INTEL_LOCAL_TEMPERATURE", "0.2"))

    local_scorer: Optional[Scorer] = None
    if scorer_mode in ("local", "hybrid") and local_model:
        local_scorer = LocalModelScorer(local_model, local_adapter, max_new_tokens, temperature)

    ollama_scorer: Optional[Scorer] = None
    if scorer_mode in ("ollama", "hybrid"):
        ollama_scorer = OllamaScorer(
            base_url=os.environ.get("INTEL_OLLAMA_BASEURL", "http://localhost:11434"),
            model=os.environ.get("INTEL_OLLAMA_MODEL", "mistral"),
            timeout=float(os.environ.get("INTEL_OLLAMA_TIMEOUT", "120")),
        )

    fallback = RuleScorer()
    if scorer_mode == "local":
        scorer = local_scorer or fallback
    elif scorer_mode == "ollama":
        scorer = ollama_scorer or fallback
    else:
        scorer = HybridScorer(local_scorer, ollama_scorer, fallback)

    planner_mode = os.environ.get("INTEL_PLANNER_MODE", "local").lower()
    local_planner: Planner = RulePlanner()
    planner_local_model = os.environ.get("INTEL_PLANNER_LOCAL_MODEL")
    planner_local_adapter = os.environ.get("INTEL_PLANNER_LOCAL_ADAPTER")
    planner_max_new_tokens = int(os.environ.get("INTEL_PLANNER_LOCAL_MAX_NEW_TOKENS", "256"))
    planner_temperature = float(os.environ.get("INTEL_PLANNER_LOCAL_TEMPERATURE", "0.2"))
    if planner_mode in ("local", "hybrid") and planner_local_model:
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
        remote_planner = OllamaPlanner(ollama_base, ollama_model, ollama_timeout)
    if planner_mode in ("remote", "ollama") and remote_planner:
        planner = remote_planner
    elif planner_mode == "hybrid":
        planner = HybridPlanner(local_planner, remote_planner)
    else:
        planner = local_planner

    cache_size = int(os.environ.get("INTEL_CACHE_SIZE", "256"))
    cache = LruCache(cache_size)

    _services["scorer"] = scorer
    _services["planner"] = planner
    _services["cache"] = cache


@app.on_event("startup")
async def _startup() -> None:
    _build_services()


def _cache_key(alert: Dict[str, Any]) -> str:
    return json.dumps(alert, sort_keys=True, default=str)


@app.post("/v1/score")
async def score(payload: Dict[str, Any]) -> Dict[str, Any]:
    alert = payload.get("alert") or {}
    _stats["score_requests"] += 1

    cache: LruCache = _services["cache"]
    key = _cache_key(alert)
    cached = cache.get(key)
    if cached:
        return cached

    scorer: Scorer = _services["scorer"]
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
async def score_batch(payload: Dict[str, Any]) -> Dict[str, Any]:
    items = payload.get("alerts") or []
    results = []
    scorer: Scorer = _services["scorer"]
    cache: LruCache = _services["cache"]

    for alert in items:
        _stats["score_requests"] += 1
        key = _cache_key(alert)
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
async def plan(payload: Dict[str, Any]) -> Dict[str, Any]:
    alert = payload.get("alert") or {}
    assessment = payload.get("assessment") or {}
    _stats["plan_requests"] += 1
    planner: Planner = _services["planner"]
    try:
        return {"plan": planner.plan(alert, assessment)}
    except Exception:
        return {"plan": RulePlanner().plan(alert, assessment)}


@app.get("/health")
async def health() -> Dict[str, Any]:
    scorer = _services.get("scorer")
    planner = _services.get("planner")
    cache: LruCache = _services.get("cache")

    local_loaded = scorer.__class__.__name__ in ("LocalModelScorer", "HybridScorer") and getattr(
        scorer, "local_scorer", None
    ) is not None

    base_url = os.environ.get("INTEL_OLLAMA_BASEURL", "http://localhost:11434")
    ollama_status = False
    if scorer.__class__.__name__ in ("OllamaScorer", "HybridScorer"):
        ollama_status = ollama_ok(base_url)

    return {
        "ok": True,
        "scorer": scorer.__class__.__name__ if scorer else None,
        "planner": planner.__class__.__name__ if planner else None,
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
