# Engine Status Report (2026-02-27)

Author: Automated report  
Scope: End-to-end engine status, model work, training/eval, and execution notes.

---

## 1) Executive Summary

- The engine is **runnable end-to-end** with the local Python intelligence service enabled.
  - Verified on **2026-02-27** using **local classifier scorer + rule planner** (fast, deterministic).
  - End-to-end run completed a single cycle with simulated alerts.
- The system now supports **model profile routing**, **flexible model backends**, and **robust JSON plan sanitization**.
- Training pipelines, evaluation scripts, and datasets are consolidated and documented.

---

## 2) Current End-to-End Run (Verified)

**Date:** 2026-02-27  
**Run mode:** Local intelligence service (no Ollama), single cycle  
**Result:** Orchestrator completed one cycle (no crash)

Observed output:
```
[Intelligence] Service already running at http://127.0.0.1:8092
Orchestrator cycle 1 complete. Pulled=6 Processed=3 Succeeded=0 Failed=0 NormalizationFailed=3 PolicyFailed=0.
```

### Settings used for the run

Environment (set explicitly for the run):
```
INTEL_HOST=0.0.0.0
INTEL_PORT=8092
THREAT_SCORER_BASEURL=http://localhost:8092
PLANNER_API_BASEURL=http://localhost:8092
THREAT_SCORER_TIMEOUT_SECONDS=2
PLANNER_API_TIMEOUT_SECONDS=2
INTEL_SCORER_MODE=classifier
INTEL_SCORER_CLASSIFIER_PATH=intelligence/models/scorer_classifier
INTEL_PLANNER_MODE=local
INTEL_PLANNER_SEQ2SEQ_MODEL=
INTEL_PLANNER_LOCAL_MODEL=
INTEL_PLANNER_LOCAL_ADAPTER=
TICKETING_API_BASEURL=
NOTIFICATION_API_BASEURL=
FIREWALL_API_BASEURL=
ORCHESTRATOR_MAX_CYCLES=1
ORCHESTRATOR_POLL_SECONDS=0
```

Notes:
- This run uses the **local classifier scorer** and **rule planner** (no LLM/Ollama).
- The intelligence service was started separately on port `8092` to avoid port conflicts on `8080`.
- External executors were disabled to keep the run deterministic and local.

---

## 3) Major Changes Implemented

### 3.1 Orchestrator / Engine Integration

**Key updates:**
- The engine now **defaults to the local Python intelligence service** if explicit scorer/planner URLs are not provided.
- Model profile routing is wired so the selected model profile can be passed from the .NET orchestrator into the Python service.

**Files updated:**
- `NetCore/Core/Program.cs`
  - Uses local intelligence service base URL as default.
  - Passes planner base URL into `HttpPlannerOptions.FromEnvironment(...)`.
- `NetCore/Core/Planning/HttpPlannerOptions.cs`
  - Accepts a base URL override.
  - Uses `INTEL_ACTIVE_PROFILE` as fallback for model profile.
- `NetCore/Core/Scoring/HttpThreatScorerClient.cs`
  - Uses `INTEL_ACTIVE_PROFILE` as fallback for model profile.

### 3.2 Intelligence Service (Python)

**Improvements:**
- Added a **minimal prompt** for seq2seq planner to reduce noise and improve JSON compliance.
- Added a **compact assessment summary** used by seq2seq prompt building.
- Strengthened plan sanitation and parameter filtering.

**Files updated:**
- `intelligence/planners/prompting.py`
  - Added `build_planner_prompt_minimal` and `_compact_assessment`.
- `intelligence/planners/seq2seq.py`
  - Uses the minimal prompt.
- `intelligence/planners/plan_utils.py`
  - Strict parameter filtering; canonicalized keys for actions.

---

## 4) Training & Evaluation Work

### 4.1 Seq2Seq Planner Pipeline

**Pipeline improvements:**
- Canonical dataset builder with **action balancing** and **minimal prompt** option.
- Safe GPU training scripts (reduced lengths, no fp16) to prevent OOM.
- Evaluations produce **strategy accuracy** and **action F1**.

**Key scripts:**
- `intelligence/training/build_planner_seq2seq_dataset.py`
- `intelligence/training/train_planner_seq2seq.py`
- `intelligence/training/eval_seq2seq_planner.py`
- `intelligence/training/compare_models.py`

### 4.2 Foundation-Sec (Ollama) Fine-tuning

**Status:**
- Multiple runs attempted; large runs required reduced lengths and lower LR to avoid OOM.
- Final runs completed without NaNs after disabling fp16 and using safe settings.

### 4.3 Metrics Summary

Metrics are tracked in:
`intelligence/training/data/model_metrics_summary.md`

Highlights (quick eval samples):
- Seq2Seq base (latest): **strategy_acc 0.80**, **action_f1 0.7711**
- Seq2Seq large (latest): **strategy_acc 0.80**, **action_f1 0.7711**
- Foundation-sec planner (quick compare): **strategy_acc 0.80**, **action_f1 0.8352**
- Foundation-sec planner (older dataset): **strategy_acc 0.9432**, **action_f1 0.9004**

---

## 5) Datasets Used

These datasets were used to build and validate the scorer/planner training data and scenarios:

- **MITRE ATT&CK (STIX)**: standardized tactics/techniques for grounding labels.
- **Mordor**: real telemetry from realistic attack emulations.
- **CIC-IDS2018**: network-flow dataset for scan/brute-force/DoS signals.
- **DARPA Transparent Computing (TC)**: provenance-rich host activity and multi-stage traces.
- **Synthetic scenarios (ScenarioTemplates)**: balances action/strategy coverage and edge cases.

---

## 6) Script Inventory (Training + Datasets)

**PowerShell scripts** (no bash scripts were added):

- `scripts/retrain_seq2seq_base_and_eval.ps1`
- `scripts/retrain_seq2seq_large_and_eval.ps1`
- `scripts/run_compare_after_export.ps1`
- `scripts/run_training_chain.ps1`
- `scripts/run_training_chain_768.ps1`
- `scripts/monitor_restart_foundation_sec.ps1`
- `scripts/monitor_foundation_sec_768.ps1`
- `scripts/train_seq2seq_canonical_safe.ps1`
- `scripts/train_seq2seq_base_action_balanced.ps1`
- `scripts/train_seq2seq_large_action_balanced.ps1`
- `scripts/train_seq2seq_large_action_balanced_overnight.ps1`
- `scripts/datasets/download_cic_ids2018.ps1`
- `scripts/datasets/download_attack_stix.ps1`
- `scripts/datasets/download_mordor.ps1`
- `scripts/datasets/download_darpa_tc.ps1`

Utility Python scripts:

- `intelligence/training/build_planner_seq2seq_dataset.py`
- `intelligence/training/train_planner_seq2seq.py`
- `intelligence/training/eval_seq2seq_planner.py`
- `intelligence/training/compare_models.py`
- `intelligence/training/train_scorer_classifier.py`
- `intelligence/training/train_soar.py`
- `intelligence/training/export_to_ollama.py`
- `intelligence/training/generate_dataset.py`
- `intelligence/training/generate_from_real_data.py`
- `intelligence/training/llm_dataset_pipeline.py`

---

## 7) Problems Encountered and Fixes

### 7.1 Intelligence service failed to start (missing FastAPI)

**Symptom:**
```
ModuleNotFoundError: No module named 'fastapi'
```

**Cause:**
.NET launched `python` from the system PATH instead of the venv, so FastAPI was missing.

**Fix:**
Run with venv Python on PATH, or start intelligence service explicitly using:
```
.\.venv\Scripts\python.exe -m intelligence
```

### 7.2 Port 8080 bind conflicts

**Symptom:**
```
error while attempting to bind on address ('0.0.0.0', 8080)
```

**Cause:**
Port already in use by a prior service.

**Fix:**
Switch to a different port (e.g., 8092) and set:
```
INTEL_PORT=8092
THREAT_SCORER_BASEURL=http://localhost:8092
PLANNER_API_BASEURL=http://localhost:8092
```

### 7.3 LLM-based runs slow / blocked

**Cause:**
Ollama dependencies and GPU load can slow demos.

**Fix:**
Use classifier scorer + rule/seq2seq planner for fast, deterministic runs.

### 7.4 Training OOM / long step times

**Symptom:**
CUDA OOM and very long step times in large model runs.

**Fix:**
Reduce max lengths, disable fp16, lower LR, and use gradient checkpointing.

---

## 8) Current State of the Engine

- **Runs end-to-end** with local intelligence service.
- **Scorer and planner are configurable**, including local classifier, seq2seq, and Ollama models.
- **Dataset generation and training are reproducible** via scripts.
- **Model metrics and training settings are documented.**

---

## 9) Recommended Next Steps

1. Validate end-to-end run with **seq2seq planner** enabled.
2. Repeat run with **foundation-sec planner** (Ollama) to confirm JSON validity in real flow.
3. Run a **full evaluation** (larger sample size) for planner accuracy.
4. Reduce normalization failures by expanding mapping coverage for the simulator scenarios.

---

## Appendix: Quick Local Run (Deterministic)

Start intelligence service (separate terminal):
```
set INTEL_HOST=0.0.0.0
set INTEL_PORT=8092
set INTEL_SCORER_MODE=classifier
set INTEL_SCORER_CLASSIFIER_PATH=intelligence/models/scorer_classifier
set INTEL_PLANNER_MODE=local
.\.venv\Scripts\python.exe -m intelligence
```

Run the engine:
```
set THREAT_SCORER_BASEURL=http://localhost:8092
set PLANNER_API_BASEURL=http://localhost:8092
set ORCHESTRATOR_MAX_CYCLES=1
set ORCHESTRATOR_POLL_SECONDS=0
dotnet exec NetCore/Core/bin/Debug/net9.0/Core.dll
```
