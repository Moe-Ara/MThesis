# Intelligence Block Report (2026-02-27)

Author: Automated report  
Scope: Python intelligence service design, implementation, issues, fixes, and usage.

---

## 1) Executive Summary

- The intelligence block is a **Python FastAPI service** that exposes scoring and planning endpoints.
- It supports **multiple model backends** (classifier, seq2seq, local HF, Ollama, hybrid) and **profile routing** via a registry.
- The service can run **standalone** or be **launched automatically** by the .NET orchestrator.
- End result: **modular intelligence** with deterministic fallbacks and predictable JSON outputs.

---

## 2) Architecture & Implementation

### 2.1 Service Overview

- Entry point: `intelligence/app.py`
- Endpoints:
  - `POST /v1/score`
  - `POST /v1/score/batch`
  - `POST /v1/plan`
  - `GET /v1/models`
  - `GET /health`

### 2.2 Model Routing

**Model registry** enables routing between profiles:
- Registry: `intelligence/models/registry.json`
- Loader: `intelligence/core/model_registry.py`
- Selector: `intelligence/core/model_selector.py`

**Profile resolution**:
1. Request `modelProfile` field or `X-Intel-Profile` header
2. `INTEL_ACTIVE_PROFILE` fallback
3. First profile in registry as default

### 2.3 Scoring Backends

- **ClassifierScorer**: deterministic model, fast.  
  File: `intelligence/scorers/classifier.py`
- **OllamaScorer**: LLM-based scoring with JSON repair.  
  File: `intelligence/scorers/ollama.py`
- **LocalModelScorer**: HF model + optional LoRA adapter.  
  File: `intelligence/scorers/local_model.py`
- **CalibratedScorer**: classifier‑based severity/confidence + LLM explanation.  
  File: `intelligence/scorers/calibrated.py`
- **HybridScorer**: primary local/classifier + fallback LLM.  
  File: `intelligence/scorers/hybrid.py`
- **RuleScorer**: deterministic fallback.  
  File: `intelligence/scorers/rule.py`

### 2.4 Planning Backends

- **RulePlanner**: deterministic fallback.  
  File: `intelligence/planners/rule.py`
- **Seq2SeqPlanner**: flan‑t5 planner trained on canonical dataset.  
  File: `intelligence/planners/seq2seq.py`
- **OllamaPlanner**: LLM-based planner with strict JSON enforcement.  
  File: `intelligence/planners/ollama.py`
- **LocalModelPlanner**: HF model + LoRA adapter.  
  File: `intelligence/planners/local_model.py`
- **HybridPlanner**: local + remote fallback.  
  File: `intelligence/planners/hybrid.py`

### 2.5 Plan Normalization / JSON Safety

Key protections:
- JSON repair attempts with strict schema enforcement.
- Parameters are **filtered to allowed keys** and normalized.
- Missing required keys are repaired with a second LLM pass (if using LLM planners).

Files:
- `intelligence/planners/plan_utils.py`
- `intelligence/planners/prompting.py`

---

## 3) Problems Encountered and Solutions

### 3.1 FastAPI missing when engine launched Python

**Symptom:**
```
ModuleNotFoundError: No module named 'fastapi'
```

**Cause:**  
.NET started system Python instead of the repo venv, so FastAPI was not installed.

**Solution:**  
Run with venv Python on PATH or explicitly start with:
```
.\.venv\Scripts\python.exe -m intelligence
```

### 3.2 Port conflicts (8080 already in use)

**Symptom:**
```
error while attempting to bind on address ('0.0.0.0', 8080)
```

**Cause:**  
Existing process bound to 8080.

**Solution:**  
Use alternate port:
```
INTEL_PORT=8092
THREAT_SCORER_BASEURL=http://localhost:8092
PLANNER_API_BASEURL=http://localhost:8092
```

### 3.3 LLM JSON invalidity

**Symptom:**  
LLM planners sometimes returned invalid JSON or missing fields.

**Solution:**  
Add JSON repair flow and sanitizer:
- Second-pass LLM repair prompt
- Strict required key checks
- Parameter filtering / normalization

### 3.4 Training instability / OOM

**Symptom:**  
Large model runs caused CUDA OOM and long step times.

**Solution:**  
Reduce max lengths, disable fp16, lower LR, use gradient checkpointing.

---

## 4) End Result

The intelligence block now:
- Supports **multiple model types** with profile routing.
- Has **deterministic fallbacks** for demos and safety.
- Produces **JSON‑safe plans** with consistent schema.
- Can run **standalone** or be launched by the engine.

---

## 5) Usage

### 5.1 Start the service (local deterministic)

```
set INTEL_HOST=0.0.0.0
set INTEL_PORT=8092
set INTEL_SCORER_MODE=classifier
set INTEL_SCORER_CLASSIFIER_PATH=intelligence/models/scorer_classifier
set INTEL_PLANNER_MODE=local
.\.venv\Scripts\python.exe -m intelligence
```

### 5.2 Start the service (seq2seq planner)

```
set INTEL_PLANNER_MODE=seq2seq
set INTEL_PLANNER_SEQ2SEQ_MODEL=intelligence/models/planner_seq2seq
.\.venv\Scripts\python.exe -m intelligence
```

### 5.3 Start the service (Ollama planner/scorer)

```
set INTEL_SCORER_MODE=ollama
set INTEL_PLANNER_MODE=ollama
set INTEL_OLLAMA_BASEURL=http://localhost:11434
set INTEL_OLLAMA_MODEL=baron-security
set INTEL_PLANNER_OLLAMA_MODEL=baron-security
.\.venv\Scripts\python.exe -m intelligence
```

### 5.4 Verify health

```
curl http://127.0.0.1:8092/health
```

### 5.5 Model profile selection (runtime)

Via body:
```
{ "modelProfile": "custom", "alert": { ... } }
```

Via header:
```
X-Intel-Profile: custom
```

---

## 6) Notes for Demos

- Use **classifier + rule planner** for fast, deterministic runs.
- Use **seq2seq planner** to demonstrate learned JSON generation.
- Use **Ollama** for qualitative LLM behavior, but expect higher latency.
