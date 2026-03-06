# Custom NN Planner Report (2026-03-01)


---

## 1) Executive Summary

The custom NN planner started as a small multi-head MLP that only saw structured features
(alert type, severity, confidence, entity flags). That baseline underperformed because it was
blind to the textual cues in hypothesis/evidence that strongly drive strategy and action
selection (e.g., "persistence tactic" -> CollectForensics).

We closed most of the gap by adding keyword features, source/technique indicators, and
interactions between alert type and severity/confidence. The model now achieves:

- Raw split (held-out): ~95.7% strategy accuracy and ~94.5% action F1
- Pipeline eval (sanitized plans): ~88-89% strategy accuracy and ~89-90% action F1

The remaining gap is mostly due to plan sanitization effects (dropping actions with missing
entities, enforcing OpenTicket/Notify, and capping actions to 4), which are not fully modeled
in the raw training objective.

---

## 2) What the Custom NN Planner Is

Model type: multi-head MLP (strategy classification + multi-label actions + priority regression)  
Training data: `intelligence/training/data/planner_seq2seq_train_compact.jsonl`  
Training script: `intelligence/training/train_planner_nn.py`  
Inference: `intelligence/planners/custom_nn.py`

Heads:
- Strategy head -> 5-class classification
- Action head -> 8-class multi-label (BlockIp, IsolateHost, DisableUser, KillProcess, QuarantineFile, CollectForensics, OpenTicket, Notify)
- Priority head -> scalar (0-100)

Why this architecture:
- Lightweight and deterministic
- Fast inference on CPU/GPU
- Easier to debug and calibrate than a full LLM

---

## 3) Baseline Limitation (Root Cause)

The pretrained LLM planner won because it can interpret textual cues in the hypothesis/evidence.
The baseline NN only saw:
- alert type
- severity/confidence
- entity presence flags

This made it blind to semantic signals that map to actions (e.g., "persistence" or "lateral movement").

---

## 4) Improvements That Drove the Accuracy Jump

### 4.1 Keyword Features (Major Gain)

We mined high-signal keywords from training prompts (hypothesis + evidence) and added a boolean
feature per keyword. Examples:
- persistence / lateral movement -> CollectForensics or ContainAndCollect
- scan / recon -> BlockIp
- malware / hash -> QuarantineFile
- brute force / failed logins -> DisableUser

This single change produced the largest improvement.

### 4.2 Source and Technique Signals

Added:
- Source one-hot: cic-ids, mitre-attack, mordor
- Technique ID presence: boolean if technique_id exists

These correlate with specific response profiles (e.g., MITRE-labeled events trending toward more
aggressive containment).

### 4.3 Interaction Features

Added interactions between:
- alert type x severity
- alert type x confidence

This helps the model learn strategy boundaries (e.g., PortScan + high severity -> Contain).

### 4.4 Class Imbalance Handling

Strategy classes were imbalanced. We introduced class weights for the strategy loss to prevent
majority-class dominance.

---

## 5) Training Results (Raw Split)

Train/test split: 7779 / 865  
Best epoch: ~130 (original run), ~150 (latest run)

Metrics (raw test split):
- Strategy accuracy: ~0.96
- Action F1: ~0.94-0.90 (varies with weighting / thresholds)
- Priority MAE: ~5.2-5.6

Example run (keyword + source features):
```
strategy_acc ≈ 0.957
action_f1 ≈ 0.945
```

---

## 6) Pipeline Evaluation (Why It Drops)

Pipeline eval uses sanitize_plan, which:
- drops actions missing required entities,
- enforces OpenTicket/Notify,
- caps action list to max 4,
- can re-derive strategy from actions.

As a result, a model that predicts "correct" actions in raw form may still lose accuracy
after sanitization.

Pipeline eval (200 samples):
- Strategy accuracy: ~0.88-0.89
- Action F1: ~0.89-0.90

This gap is expected unless the model is explicitly aligned to sanitization rules.

---

## 7) What We Added to Align with Pipeline

### 7.1 Entity-Aware Action Mask

At inference time, actions that require missing entities are skipped.
This avoids generating actions that will be dropped by sanitize_plan.

### 7.2 Action Cap Alignment

We limit predictions to the top 4 actions by probability and ensure a safe action
(OpenTicket/Notify) exists. This mirrors sanitize_plan behavior.

### 7.3 Threshold Tuning (Per Action)

We added per-action thresholds (stored in meta.json) to calibrate the multi-label
head to the dataset. This makes the action head more precise.

---

## 8) Why It Still Does Not Hit 95% in Pipeline Eval

The remaining error is mostly structural:
1. Loss mismatch: training optimizes raw labels, not sanitized outputs.
2. Text compression: the prompt truncates hypothesis/evidence, losing subtle cues.
3. Action interdependencies: some actions are mutually exclusive, but the loss does not encode that.
4. Dataset noise: some samples have weak or ambiguous signals.

---

## 9) What Would Likely Push It to 95% (Next Steps)

1. Train on sanitized targets  
   Regenerate targets by running the same sanitize_plan logic during dataset creation, then train on those outputs.

2. Replace keyword flags with TF-IDF features  
   Use a small TF-IDF vector (e.g., 256 dims) for hypothesis/evidence instead of binary keywords.

3. Add context features  
   Train on compact prompts that include assetCriticality, privileged, exposure, and timeSensitivity.

4. Per-action calibration  
   Tune thresholds on a validation set to maximize micro-F1 (not per-action F1).

5. Expand dataset with action-balanced samples  
   Oversample rare actions (KillProcess, QuarantineFile) for better recall.

---

## 10) Files and Artifacts

- `intelligence/training/train_planner_nn.py` - training and evaluation loop
- `intelligence/planners/custom_nn.py` - inference implementation
- `intelligence/training/eval_planner_nn.py` - pipeline-aligned evaluation
- `intelligence/models/planner_nn/` - saved model (model.pt + meta.json + eval_results.json)
- `intelligence/training/data/nn_eval.json` - pipeline evaluation output

---

## 11) Final Status

The custom NN planner is competitive with the seq2seq compact model, especially for
deterministic demos or CPU-only environments. It remains simpler and cheaper to run
than LLM-based planners, and it can be improved further using the steps above if
95%+ pipeline accuracy is required.
