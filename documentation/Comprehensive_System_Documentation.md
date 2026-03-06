Comprehensive System Documentation (Reasoning SIEM Engine)
==========================================================

Last updated: 2026-03-06

This document is an end‑to‑end, verbose explanation of the system architecture,
design decisions, theory and practical implementation, current results, and how
to modify or extend each component. It is intended as a thesis reference.

-------------------------------------------------------------------------------
1) Executive Summary
-------------------------------------------------------------------------------

Goal
----
Build a SIEM plugin that behaves like a reasoning engine, not a generic alert
dashboard. The differentiators are:

- **Explainable risk scoring** (with confidence and context multipliers).
- **Action planning** that produces a machine‑actionable response plan.
- **Policy governance** to approve/deny actions and capture rationale.
- **Auditable execution** with action‑level status and detailed logs.
- **Learning loops** (feedback + investigation traces + recommendations).
- **Reasoning console** UI to show raw alert → normalized alert → score → plan →
  policy → execution → audit in one place.

Why this architecture
---------------------
Traditional SIEMs report alerts and rely heavily on manual triage. SOAR systems
automate actions but are often deterministic playbooks without adaptive scoring
and learning. The system here bridges those gaps by:

- **Separating scoring and planning**: score = “what’s happening / how risky”,
  plan = “what to do next.”
- **Making reasoning explicit**: every decision has a traceable explanation,
  even if the model does not provide one.
- **Embedding policy gates**: enforcement sits between planning and execution.

-------------------------------------------------------------------------------
2) System Architecture (Layered)
-------------------------------------------------------------------------------

High‑level layers
----------------
1) **Domain**
   - Entities: alerts, assessments, plans, actions.
   - Deterministic decision rules (e.g., sanitation, strategy derivation).

2) **Application**
   - Orchestrator: coordinates ingest → normalize → score → plan → policy → execute.
   - Use‑cases: scoring, planning, policy evaluation, execution routing.

3) **Infrastructure**
   - SIEM connectors (Wazuh / simulator).
   - Persistence (audit logs, case DB).
   - Model hosting (Python FastAPI intelligence service).

4) **API**
   - FastAPI service for scoring and planning.
   - REST integration into .NET engine.

5) **UI**
   - Reasoning Console (demo UI).
   - Case dashboard (case UI).

Why this layering
----------------
- **Testability**: domain logic can be unit tested without infrastructure.
- **Interchangeability**: multiple model backends (custom NN, seq2seq, Ollama).
- **Traceability**: every stage emits structured data.

-------------------------------------------------------------------------------
3) Data Flow (End‑to‑End)
-------------------------------------------------------------------------------

Pipeline
--------
1) **Ingestion**
   - Wazuh (real) or Simulator (local).
2) **Normalization**
   - Map raw alert → normalized alert schema.
3) **Enrichment**
   - Optional contextual enrichment (asset, identity, intel).
4) **Scoring**
   - Compute threat assessment: severity, confidence, hypothesis, evidence.
5) **Planning**
   - Produce response plan: strategy, actions, rollback actions, rationale.
6) **Policy**
   - Approve/deny actions with reasoning.
7) **Execution**
   - Execute (stubbed or HTTP) actions and record results.
8) **Audit + Case**
   - Audit log and case DB capture all artifacts.
9) **UI**
   - Display full trace, reasoning, and action outcomes.

-------------------------------------------------------------------------------
4) Ingestion & Connectors
-------------------------------------------------------------------------------

Implementation
--------------
- **Wazuh connector**: polls/consumes Wazuh alerts and maps them into raw alerts.
- **Simulator connector**: generates synthetic threats using templates.

Key code
--------
- Wazuh connector: `NetCore/Core/Connectors/Wazuh/*`
- Simulator: `NetCore/Core/Simulation/*`
- Orchestrator: `NetCore/Core/AgentOrchestrator.cs`

Why this approach
-----------------
Real SIEM connectors are noisy and inconsistent. A simulator allows deterministic
testing, while Wazuh integration demonstrates realistic “plug‑in” behavior.

-------------------------------------------------------------------------------
5) Normalization
-------------------------------------------------------------------------------

Purpose
-------
Different SIEMs produce different schemas. Normalization unifies these into a
consistent alert model so scoring/planning can be model‑agnostic.

Implementation
--------------
- Mapping registry chooses a mapper based on SIEM source.
- Simulation mapper extracts entities from the raw payload.
- Validation checks required fields.

Key code
--------
- `NetCore/Core/Simulation/SimulationAlertMapper.cs`
- `NetCore/Core/NormalizationPipeline/*`

Notable decisions
-----------------
- Entities are explicitly mapped (`hostId`, `username`, `srcIp`, etc.) to ensure
  consistent model features.
- `RawPayload` is preserved to allow downstream models to extract indicators.

-------------------------------------------------------------------------------
6) Enrichment
-------------------------------------------------------------------------------

Purpose
-------
Enrichment attaches asset criticality, user privilege, threat intel, and
historical context to alert records.

Implementation
--------------
Enrichment providers are pluggable and merged into `EnrichmentContext`.

Key code
--------
- `NetCore/Core/NormalizationPipeline/Enrichers/*`
- `NetCore/Core/NormalizationPipeline/DefaultEnrichmentMerger.cs`

Notes
-----
The current demo uses a minimal enrichment pipeline (placeholders). The schema
is present to support future enrichment data sources (CMDB, IAM, intel feeds).

-------------------------------------------------------------------------------
7) Scoring (Threat Assessment)
-------------------------------------------------------------------------------

Purpose
-------
Transform normalized alerts into structured assessments that drive policy and
planning.

Assessment schema
-----------------
- severity (0–100)
- confidence (0–1)
- hypothesis (short explanation)
- evidence (1–3 short indicators)

Implementations
---------------
1) **Classifier scorer (fast)**
   - Uses a trained classifier to predict severity label + confidence.
   - Evidence derived from entities + raw payload fields.

2) **Ollama scorer (explainable)**
   - LLM‑based JSON output.

3) **Calibrated scorer**
   - Combines classifier (fast) with LLM explainer.

Key code
--------
- `intelligence/scorers/classifier.py`
- `intelligence/scorers/ollama.py`
- `intelligence/scorers/calibrated.py`
- `NetCore/Core/Scoring/HttpThreatScorerClient.cs`

Why this approach
-----------------
Classifier gives speed and stability; LLM provides richer hypotheses. The
calibrated scorer balances speed + interpretability.

Recent improvement
------------------
The scoring payload now includes:
- `ruleName`, full entities, and `rawPayload`
This enables richer evidence strings (e.g., `dst_ip`, `process`, `technique_id`).

-------------------------------------------------------------------------------
8) Planning (Response Plan)
-------------------------------------------------------------------------------

Purpose
-------
Convert assessment + alert context into a response plan that can be evaluated
by policy and executed automatically or manually.

Plan schema
-----------
- strategy: ObserveMore | NotifyOnly | Contain | ContainAndCollect | EscalateToHuman
- priority: 0–100
- actions: list of action objects (type + parameters + risk + expectedImpact)
- rollbackActions
- rationale (list)
- tags (metadata)
- reasoning (structured explanation)

Implementations
---------------
1) **Custom NN planner**
   - Multi‑head MLP trained on compact dataset.
   - Feature extraction includes entities + keyword/TF‑IDF.
   - Achieved ~96% strategy accuracy / ~97% action F1 (reasoning dataset eval).

2) **Seq2Seq planner**
   - Flan‑T5 models trained with pipe‑delimited output.

3) **Ollama planner**
   - LLM JSON output with self‑repair logic.

4) **Rule planner (fallback)**
   - Deterministic rules for strategy/actions.

Key code
--------
- Planners: `intelligence/planners/*`
- Sanitizer & reasoning: `intelligence/planners/plan_utils.py`
- Model registry: `intelligence/core/model_registry.py`

Why sanitize_plan exists
------------------------
Model outputs can be invalid, inconsistent, or missing required parameters.
`sanitize_plan`:
- Normalizes strategy
- Ensures action parameters are valid and feasible
- Enforces safe actions when confidence is low
- Adds rollback actions if needed
- Injects reasoning if missing

-------------------------------------------------------------------------------
9) Reasoning (Derived vs Model‑Provided)
-------------------------------------------------------------------------------

Problem
-------
LLMs may omit reasoning or return partial explanations. We still need consistent
audit trails and UI‑visible explanations.

Solution
--------
`sanitize_plan` constructs a reasoning block if the planner didn’t supply one.
This includes:
- summary (from assessment hypothesis or fallback)
- evidence (from assessment or entity values)
- constraints (policy/limit constraints)
- action_justifications (default rationales per action)

Key code
--------
- `intelligence/planners/plan_utils.py`
- notes: `documentation/notes/reasoning_derivation.md`

-------------------------------------------------------------------------------
10) Policy Engine
-------------------------------------------------------------------------------

Purpose
-------
Policy gates ensure actions are safe, approved, and compliant.

Implementation
--------------
Policies are JSON‑driven and data‑driven.

Key code
--------
- `NetCore/Core/Policy/*`
- `policy_config.json`

Why policies are required
-------------------------
Even a perfect planner must be bounded by org policy and safety constraints.
This provides explainable enforcement rather than hard‑coding behavior.

-------------------------------------------------------------------------------
11) Execution Pipeline
-------------------------------------------------------------------------------

Purpose
-------
Execute approved actions, track outcomes, and log evidence.

Implementation
--------------
Executors are pluggable:
- Ticketing
- Notification
- Firewall
- Host isolation / user access

Each action is routed to the proper executor via `ExecutorRouter`.

Key code
--------
- `NetCore/Core/Execution/*`
- Executors: `NetCore/Core/Execution/Executors/*`

Results
-------
The demo uses local stub executors by default, but HTTP‑based executors are
available by setting API base URLs in `.env`.

-------------------------------------------------------------------------------
12) Auditing & Case Management
-------------------------------------------------------------------------------

Auditing
--------
- Every stage emits audit entries into JSONL logs.
- Used for demo trace display and forensic reconstruction.

Key code
--------
- `NetCore/Core/Auditing/*`

Case management
---------------
- Simple SQLite case store for persisted incidents.

Key code
--------
- `NetCore/Core/CaseManagement/SqliteCaseManager.cs`
- UI: `case_ui/`

-------------------------------------------------------------------------------
13) Intelligence Service (Python)
-------------------------------------------------------------------------------

Purpose
-------
Hosts scorer and planner models behind a FastAPI API. .NET engine communicates
with this service via HTTP.

Key endpoints
-------------
- POST `/v1/score`
- POST `/v1/plan`
- GET `/health`

Key code
--------
- `intelligence/app.py`
- `intelligence/core/model_registry.py`

Why a separate service
----------------------
Separates ML dependencies from .NET runtime, allows flexible model swaps, and
supports local/remote providers.

-------------------------------------------------------------------------------
14) Model Registry & Profiles
-------------------------------------------------------------------------------

Purpose
-------
Enable model switching without code changes.

Implementation
--------------
`intelligence/models/registry.json` defines profiles with scorer + planner types.
The active profile is used by the service unless overridden per request.

Examples
--------
- `foundation-sec` (LLM planner)
- `custom-nn-reasoning-20260306` (custom NN planner)

-------------------------------------------------------------------------------
15) Dataset Generation & Training
-------------------------------------------------------------------------------

Datasets used
-------------
Documented in `documentation/README.md`:
- MITRE ATT&CK (STIX)
- Mordor
- CIC-IDS2018
- DARPA TC
- Synthetic scenarios

Key training scripts
--------------------
- `intelligence/training/train_planner_nn.py`
- `intelligence/training/train_planner_seq2seq.py`
- `intelligence/training/train_scorer_classifier.py`
- `intelligence/training/compare_models.py`

Reasoning dataset
-----------------
The dataset `planner_seq2seq_train_compact_reasoning.jsonl` was derived by
injecting reasoning via `sanitize_plan`.

Builder:
- `intelligence/training/build_planner_reasoning_dataset.py`

-------------------------------------------------------------------------------
16) UI / Reasoning Console
-------------------------------------------------------------------------------

Purpose
-------
Expose the entire reasoning flow (alert → normalized → score → plan → policy →
execution → audit) in a single UI.

Key pieces
----------
- Backend: `demo_ui/app.py`
- Frontend: `demo_ui/static/*`

Shows
-----
- Raw alert
- Normalized alert
- Score & reasoning
- Plan & reasoning
- Policy checks
- Execution status
- Audit log
- Trace recommendations

-------------------------------------------------------------------------------
17) Case Dashboard
-------------------------------------------------------------------------------

Purpose
-------
Display persisted cases stored in SQLite.

Key pieces
----------
- `case_ui/app.py`
- `case_ui/static/*`

-------------------------------------------------------------------------------
18) Demo Scripts
-------------------------------------------------------------------------------

Primary end‑to‑end run
----------------------
`scripts/demo_custom_nn.ps1`:
- Runs full pipeline for a simulated alert.
- Uses custom NN reasoning planner.
- Writes trace to `data/demo_trace.json`.

UI scripts
----------
- `scripts/demo_ui.ps1`: launches reasoning console and case dashboard.
- `scripts/case_ui.ps1`: case dashboard only.

-------------------------------------------------------------------------------
19) Current Results (As of 2026‑03‑06)
-------------------------------------------------------------------------------

Custom NN planner (reasoning dataset)
-------------------------------------
Eval (865 samples):
- strategy_acc: 0.9653
- strategy_acc_relaxed: 0.9665
- action_f1: 0.9729

Model path:
`intelligence/models/planner_nn_reasoning_20260306`

Reasoning integration
---------------------
Reasoning now appears in `plan.tags.planner_reasoning` for UI display, even when
the model itself doesn’t supply reasoning.

-------------------------------------------------------------------------------
20) Modifying the System
-------------------------------------------------------------------------------

Add a new scenario
------------------
1) Add constant + builder in `NetCore/Core/Simulation/ScenarioTemplates.cs`.
2) (Optional) force scenario with `SIMULATOR_FORCE_SCENARIO` in demo script.

Add a new planner
-----------------
1) Implement planner class in `intelligence/planners/`.
2) Register it in `intelligence/core/model_registry.py`.
3) Add a profile in `intelligence/models/registry.json`.

Change policy rules
-------------------
Edit `policy_config.json` or add new rules in `NetCore/Core/Policy/*`.

Change UI displays
------------------
Edit `demo_ui/static/app.js` and `demo_ui/static/styles.css`.

-------------------------------------------------------------------------------
21) Known Limitations (Current)
-------------------------------------------------------------------------------

- Enrichment is minimal (placeholders); real integrations are not wired.
- Scoring evidence is still heuristic; LLM explanations can be added if desired.
- Some actions are stub executors (safe for demo).
- Not all connectors are event‑push yet (Wazuh push integration is limited).

-------------------------------------------------------------------------------
22) Why This Is Not “Just Another SIEM”
-------------------------------------------------------------------------------

Key differences
---------------
- The pipeline is **reasoning‑centric**; every decision has a rationale.
- Models are **first‑class**, pluggable components with profiles.
- **Policy enforcement** is a separate stage, not implicit logic.
- UI is built around **decision explanation**, not dashboards.

SOAR vs this system
-------------------
- SOAR typically executes fixed playbooks. This system selects actions
  dynamically based on risk + context + policy.
- The decision logic is transparent and auditable rather than hidden in scripts.

-------------------------------------------------------------------------------
23) Scaling & Growth Path
-------------------------------------------------------------------------------

Immediate upgrades
------------------
- Add real enrichment (CMDB, IAM, threat intel feeds).
- Add asynchronous ingestion and processing queue.
- Improve confidence calibration and evidence generation.

Long‑term vision
----------------
- Multi‑stage incident reasoning with long‑term memory.
- Analyst feedback integrated into continuous training loops.
- Federated SIEM integrations with streaming event ingestion.

-------------------------------------------------------------------------------
24) References (Local)
-------------------------------------------------------------------------------

- `documentation/README.md` – dataset and script inventory
- `documentation/notes/reasoning_derivation.md` – planner reasoning derivation
- `documentation/Docs/*` – diagrams and architecture reports

-------------------------------------------------------------------------------
25) Development Narrative (Why, How, and What Changed)
-------------------------------------------------------------------------------

Why this project exists
-----------------------
The goal was to move beyond classic “alert display” SIEM into a **reasoning
engine**: a system that interprets, explains, and recommends actions rather than
only reporting events. The research focus was on explainability, risk‑based
ranking, and the ability to learn from analyst feedback.

Key expectations at start
-------------------------
- A full end‑to‑end pipeline from raw alerts to execution outcomes.
- Explainable scoring and action planning (not just opaque ML outputs).
- Usable demo UI that makes reasoning visible.
- Ability to switch models easily (local vs remote, neural vs rule).
- Demonstrate learning loops and planning recommendations.

What was built
--------------
1) A **layered engine** in .NET with normalized alert schema and strict policy
   enforcement.
2) A **Python intelligence service** hosting multiple scoring/planning models,
   selectable by profile.
3) An **audit and case persistence** system (JSONL + SQLite).
4) A **reasoning console UI** that shows the entire decision chain.
5) A **dataset/training pipeline** that supports classifier, seq2seq, and
   custom NN planners with comparison tooling.

How the system evolved
----------------------
- Early prototypes relied on rule planning and basic scoring.
- Realistic datasets were added (CIC‑IDS2018, MITRE ATT&CK, Mordor, DARPA TC).
- Seq2seq planners were introduced but struggled with JSON validity and speed.
- Custom NN planner improved results once **textual keyword + TF‑IDF features**
  were added (major jump in accuracy).
- Reasoning was added as a derived artifact to avoid reliance on LLM‑generated
  explanations for every run.

Key decisions and why they were made
------------------------------------
- **Separate scoring and planning**: simpler model targets, clearer evaluation.
- **Sanitize all plans**: ensures policy/execution safety regardless of model.
- **Model registry**: enables fast switching for demos and comparisons.
- **Derived reasoning**: guarantees explanations even if models fail.

-------------------------------------------------------------------------------
26) Expectations vs Results
-------------------------------------------------------------------------------

Expected outcomes
-----------------
- A fully connected pipeline producing consistent outputs.
- Model‑backed planning with measurable accuracy.
- Clear UI that highlights the “reasoning engine” differentiation.

Actual results (current)
------------------------
- End‑to‑end pipeline is functional and demo‑ready.
- Custom NN planner achieved **~96% strategy accuracy / ~97% action F1**.
- Reasoning is consistent and traceable in UI.
- Policy and execution stages are working with stub or HTTP executors.
- UI clearly shows evidence and decision reasoning for each stage.

Gaps that remain
---------------
- Enrichment sources are minimal (placeholders).
- Some SIEM connectors are still polling or simulated.
- LLM scoring remains optional due to cost/latency.
- Some executors are still stubs in local demo mode.

-------------------------------------------------------------------------------
27) Improvements: What Could Be Done and Why It’s Not Yet
-------------------------------------------------------------------------------

Possible improvements
---------------------
1) **Stronger enrichment**:
   - Integrate real CMDB/IAM/threat intel feeds.
   - Impact: richer context and better confidence calibration.

2) **Streaming ingestion**:
   - Replace polling with event push for Wazuh or syslog streams.

3) **More advanced models**:
   - Multi‑modal or long‑context models for richer evidence extraction.
   - Reinforcement signals from analyst feedback loops.

4) **Enterprise‑grade scaling**:
   - Async queues, horizontal scaling, distributed case stores.

Why they are not fully implemented
---------------------------------
- Dataset curation and fine‑tuning requires significant time and labeled data.
- Infrastructure integrations are environment‑specific and costly to test.
- For the thesis demo, stability and explainability were prioritized over scale.

-------------------------------------------------------------------------------
28) Pros and Cons (System‑Level)
-------------------------------------------------------------------------------

Pros
----
- **Explainable reasoning** at every stage (score → plan → policy).
- **Model‑agnostic design** with profile switching.
- **Deterministic safeguards** (sanitization, policy enforcement).
- **Clear demo value**: reasoning console makes the system distinctive.
- **High accuracy** on the custom NN planner for planning tasks.

Cons / Tradeoffs
----------------
- LLM planning can be slow and inconsistent without sanitization.
- Enrichment is minimal; full enterprise context is not included.
- Simulated alerts can skew perception if not mixed with benign examples.
- Training pipelines are non‑trivial and require careful dataset tuning.

-------------------------------------------------------------------------------
29) How to Explain the System in One Paragraph
-------------------------------------------------------------------------------

This system is a reasoning‑first SIEM plugin that ingests alerts, normalizes them,
scores risk with confidence, generates a response plan, checks that plan against
policy, executes approved actions, and logs every decision with evidence. Unlike
traditional SIEMs and SOAR playbooks, it surfaces **why** each decision was made,
supports model switching for planning, and provides a UI that exposes the full
decision chain in one place, making it demonstrably explainable and auditable.

