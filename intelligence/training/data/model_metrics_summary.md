# Model Metrics Summary

## Planner models comparison

| Model | Type | Eval dataset | Samples | strategy_acc | strategy_acc_relaxed | action_f1 | Notes |
|---|---|---|---:|---:|---:|---:|---|
| Seq2Seq (base, latest) | flan-t5-base | `seq2seq_eval.json` (canonical + action-balanced) | 30 | 0.80 | 1.00 | 0.7711 | Fast baseline; minimal prompt. |
| Seq2Seq (compact, latest) | flan-t5-base | `seq2seq_eval_compact.json` (compact prompt) | 100 | 0.90 | 0.98 | 0.9113 | Best overall seq2seq accuracy to date. |
| Seq2Seq (large, latest) | flan-t5-large | `seq2seq_eval_large.json` (canonical + action-balanced) | 30 | 0.80 | 1.00 | 0.7711 | Larger model; fp16 disabled for stability. |
| Seq2Seq (older compare) | flan-t5-base | `model_compare_planner.json` | 30 | 0.5667 | N/A | 0.6778 | Pre-action-balanced dataset. |
| Custom NN planner (keyword+source) | Custom NN | `nn_eval.json` (compact prompt) | 200 | 0.885 | 0.915 | 0.8937 | Pipeline eval via sanitize_plan. |
| Foundation-sec (planner) | Ollama LLM | `model_compare_planner.json` | 30 | 0.80 | N/A | 0.8352 | Best action_f1 in quick compare. |
| Foundation-sec (planner, older) | Ollama LLM | `model_compare.json` | 100 | 0.9432 | N/A | 0.9004 | Earlier eval on older dataset. |
| Baron-security (baseline) | Ollama LLM | `baseline_metrics.json` | N/A | N/A | N/A | N/A | Qualitative-only baseline; no aggregate metrics. |

## Scorer models comparison

| Model | Type | Eval dataset | Samples | severity_mae | severity_class_acc | confidence_mae | Notes |
|---|---|---|---:|---:|---:|---:|---|
| Custom classifier (joblib) | ML classifier (your custom NN baseline) | `model_compare.json` | 100 | 8.30 | 0.75 | 0.1651 | Deterministic, fast. |
| Foundation-sec (scorer) | Calibrated (classifier + LLM explainer) | `model_compare.json` | 100 | 7.15 | 0.68 | 0.1051 | Better confidence calibration. |
| Baron-security (baseline) | Ollama LLM | `baseline_metrics.json` | N/A | N/A | N/A | N/A | Produces mostly low/zero scores; no aggregates. |

## Notes
- Large model completed without NaNs after disabling fp16 and lowering LR.
- Full eval (709 samples) not run yet; quick eval uses 30 samples.
- If "custom neural network" refers to a different scorer than the joblib classifier, point me to its metrics file and I will add it.

## Datasets used (and why)

- **MITRE ATT&CK (STIX)**: standardized tactics/techniques and authoritative descriptions used to ground labels and reasoning.
- **Mordor**: real telemetry from realistic attack emulations (Sysmon/process/registry) to train on how attacks actually look in logs.
- **CIC-IDS2018**: large labeled network-flow dataset for port scans, brute force, and DoS patterns.
- **DARPA Transparent Computing (TC)**: provenance-rich host activity and multi-stage traces to add sequence context.
- **Synthetic scenarios (ScenarioTemplates)**: fills gaps and balances action/strategy coverage; ensures consistent plan schemas and edge cases.

## Training and dataset scripts

Note: all scripts added here are PowerShell (`.ps1`) scripts (no bash scripts were added).

### PowerShell scripts

- `scripts/retrain_seq2seq_base_and_eval.ps1`: retrains flan-t5-base on the canonical dataset and runs a quick eval.
- `scripts/retrain_seq2seq_large_and_eval.ps1`: builds canonical dataset, retrains flan-t5-large, then evals.
- `scripts/demo_custom_nn.ps1`: runs a one-cycle demo using the custom NN planner profile.
- `scripts/run_compare_after_export.ps1`: waits for `export_to_ollama` to finish, then runs planner comparison.
- `scripts/run_training_chain.ps1`: trains foundation-sec planner then retrains seq2seq base.
- `scripts/run_training_chain_768.ps1`: same as above but with max length 768 and safer alloc settings.
- `scripts/monitor_restart_foundation_sec.ps1`: checks for stalled training and restarts the chain.
- `scripts/monitor_foundation_sec_768.ps1`: same idea for the 768-length run.
- `scripts/train_seq2seq_canonical_safe.ps1`: safe seq2seq base training + eval on canonical dataset.
- `scripts/train_seq2seq_base_action_balanced.ps1`: builds action-balanced dataset, trains base, quick eval.
- `scripts/train_seq2seq_large_action_balanced.ps1`: action-balanced dataset, trains large, quick eval.
- `scripts/train_seq2seq_large_action_balanced_overnight.ps1`: lower-memory large training for overnight runs.
- `scripts/demo_ui.ps1`: starts the demo UI (reads `data/demo_trace.json`).
- `scripts/datasets/download_cic_ids2018.ps1`: downloads CIC-IDS2018 data.
- `scripts/datasets/download_attack_stix.ps1`: downloads MITRE ATT&CK STIX data.
- `scripts/datasets/download_mordor.ps1`: downloads Mordor/Security Datasets.
- `scripts/datasets/download_darpa_tc.ps1`: downloads DARPA Transparent Computing data.

### Utility Python scripts

- `intelligence/training/build_planner_seq2seq_dataset.py`: builds canonical seq2seq dataset (optional action balancing).
- `intelligence/training/train_planner_seq2seq.py`: trains the seq2seq planner (flan-t5-*).
- `intelligence/training/eval_seq2seq_planner.py`: evaluates planner output (strategy accuracy + action F1).
- `intelligence/training/compare_models.py`: compares planner/scorer models and writes metrics JSON.
- `intelligence/training/train_scorer_classifier.py`: trains the classifier scorer baseline.
- `intelligence/training/train_soar.py`: fine-tunes the foundation-sec planner via LoRA.
- `intelligence/training/export_to_ollama.py`: exports a fine-tuned adapter into an Ollama-ready format.
- `intelligence/training/generate_dataset.py`: generates synthetic scorer/planner datasets.
- `intelligence/training/generate_from_real_data.py`: builds datasets from real logs (when available).
- `intelligence/training/llm_dataset_pipeline.py`: LLM-assisted dataset generation pipeline.
