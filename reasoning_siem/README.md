# Reasoning SIEM Demo

A single runnable demo that showcases adaptive risk-weighted correlation (Option A) and the analyst cognitive loop (Option D). The UI surfaces explainable scoring, feedback-driven weight updates, and next-step recommendations from investigation traces.

## Run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r reasoning_siem/requirements.txt
python reasoning_siem/main.py
```

Open http://localhost:8008/ui/triage

Sample data seeds automatically on first run. To generate it manually:

```bash
python reasoning_siem/scripts/generate_sample_data.py
```

## What makes this different

- **Risk scoring is explainable and adaptive**: `risk_score = (bias + sum(weight_i * feature_i)) * context_multiplier * confidence` with visible feature contributions.
- **Analyst feedback updates the model online**: FP/TP/NMI feedback shifts weights and immediately changes ranking.
- **Investigation assistant**: traces build a transition model that recommends next steps in real time.

## Data locations

- Scoring weights: `reasoning_siem/data/weights.json`
- Feedback audit log: `reasoning_siem/data/feedback_log.jsonl`
- Model update diffs: `reasoning_siem/data/weight_diff_log.jsonl`
- Investigation traces: `reasoning_siem/data/trace_log.jsonl`
- Normalized events + context: `reasoning_siem/data/events.json`

## Architecture

- `reasoning_siem/domain` - entities, scoring model, recommender
- `reasoning_siem/application` - use cases (triage, feedback, trace, analytics)
- `reasoning_siem/infrastructure` - persistence + repositories + sample data generator
- `reasoning_siem/api` - FastAPI endpoints
- `reasoning_siem/ui` - HTML/CSS/JS frontend

## Demo script

1) Open **Triage** and show ranked incidents with risk score, confidence, context multipliers, and top reasons.
2) Open an incident to show the explanation panel and reasoning breakdown.
3) Click **Mark False Positive** with a severity override and show the weight diff message.
4) Return to **Triage** and refresh to show the ranking change for similar incidents.
5) In **Incident Detail**, click a few investigation actions to show next-step recommendations updating.
6) Open **Learning & Audit** to show the feedback log and weight diff history.

## Tests

```bash
pytest reasoning_siem/tests
```


