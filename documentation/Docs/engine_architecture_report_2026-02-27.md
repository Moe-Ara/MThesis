# Engine Architecture Report (2026-02-27)

Author: Automated report  
Scope: End-to-end engine architecture, design decisions, problems and fixes, alternatives considered, and differentiation vs SIEM/SOAR.

---

## 1) Executive Summary

This engine is a **reasoning-first incident pipeline** that takes normalized alerts, produces threat assessments, generates action plans, applies policy, and executes actions. The key differentiator is **model-driven reasoning** with deterministic fallbacks and explainable outputs (scoring + planning), rather than purely rule-based correlation or static SOAR playbooks.

The architecture is modular:
- **Connectors** ingest from SIEM or simulation.
- **Normalization** produces consistent event schemas.
- **Scoring** produces severity/confidence with explanations.
- **Planning** generates a structured response plan.
- **Policy** evaluates constraints and approvals.
- **Execution** performs actions via pluggable executors.

The engine runs end-to-end with a local Python intelligence service and supports multiple model backends (classifier, seq2seq, Ollama, hybrid) via a model registry.

---

## 2) System Architecture (High-Level)

### 2.1 Core Pipeline (C#)

The C# engine is the orchestrator. Core flow:

1. **SIEM Connector** pulls alerts or listens to a webhook.
2. **Normalization Pipeline** maps raw alerts to normalized events.
3. **Scoring** calls the intelligence service to obtain severity/confidence and evidence.
4. **Planning** calls the intelligence service to produce a plan (JSON).
5. **Policy Engine** applies policy rules, approvals, and constraints.
6. **Execution Pipeline** routes actions to executors (ticketing, firewall, notification, etc.).
7. **Auditing** captures execution and decision traces (audit log).

Key modules (folder-level):
- `NetCore/Core/Connectors`: SIEM connectors (Wazuh + simulator).
- `NetCore/Core/NormalizationPipeline`: mapping + enrichment.
- `NetCore/Core/Scoring`: HTTP client + fallback scoring.
- `NetCore/Core/Planning`: HTTP client + fallback planner.
- `NetCore/Core/Policy`: policy engine and approval workflow.
- `NetCore/Core/Execution`: executors and routing.
- `NetCore/Core/Auditing`: audit log.

### 2.2 Intelligence Service (Python)

The intelligence block is a FastAPI service that exposes:
- `/v1/score`
- `/v1/plan`
- `/v1/models`
- `/health`

It supports multiple backends via a **model registry**:
`intelligence/models/registry.json`

Backends include:
- Classifier scoring (deterministic)
- Seq2Seq planning (flan-t5)
- Ollama-based LLM scoring/planning
- Local HF models with optional adapters
- Hybrid / calibrated modes

---

## 3) Design Decisions (and Why)

### 3.1 Separate Intelligence Service

**Decision:** Split scoring/planning into a Python service.  
**Why:**  
1) ML tooling and model ecosystems are Python-first.  
2) Allows independent scaling (CPU/GPU nodes).  
3) Avoids coupling inference to core engine release cycles.

### 3.2 Strict JSON Output + Sanitization

**Decision:** Enforce JSON schema in planners, sanitize fields, and repair invalid output.  
**Why:**  
Plans must be reliable for automated execution. LLM output must be validated and normalized.

### 3.3 Model Registry and Profiles

**Decision:** Use a registry and profile selection for models.  
**Why:**  
Supports easy A/B testing, demos, and safe fallback profiles without code changes.

### 3.4 Deterministic Fallbacks

**Decision:** Keep rule-based scorer and planner as fallback.  
**Why:**  
Ensures the engine remains operational if models are unavailable or slow.

### 3.5 Minimal Prompts for Seq2Seq Planner

**Decision:** Use compact prompt format for seq2seq training/inference.  
**Why:**  
Short prompts reduce errors, speed up inference, and improve JSON accuracy.

---

## 4) Problems Faced and Solutions

### 4.1 Intelligence Service Fails at Startup

**Symptom:** FastAPI missing (`ModuleNotFoundError`).  
**Root cause:** .NET launched system Python instead of venv.  
**Fix:** Ensure venv Python is used (PATH or explicit). Provide .env + startup checks.

### 4.2 Port Conflicts on 8080

**Symptom:** Bind error for 8080.  
**Root cause:** Previous service occupying port.  
**Fix:** Use alternate ports (8090/8091/8092) and pass base URLs to orchestrator.

### 4.3 Invalid JSON From LLM Planner

**Symptom:** Missing fields or malformed JSON.  
**Fix:** Schema repair + sanitation pass, strict key requirements, parameter filtering.

### 4.4 Large-Model Training OOM / Slow

**Symptom:** CUDA OOM, long step times, instability.  
**Fix:** Reduce max lengths, disable fp16, lower LR, enable gradient checkpointing.

---

## 5) Alternative Approaches Considered (and Rejected)

### 5.1 Pure SOAR Playbooks

**Rejected because:**  
Static playbooks lack adaptiveness for novel alerts and do not leverage evidence-based reasoning or feedback learning.

### 5.2 Pure Rule-Based Correlation

**Rejected because:**  
Rules alone cannot generalize across noisy or incomplete logs, and require heavy manual tuning.

### 5.3 End-to-End LLM for Everything

**Rejected because:**  
High latency, nondeterministic outputs, and brittle JSON integrity. We instead use **LLM only where it adds value**, with deterministic fallbacks.

### 5.4 Single-Monolith Architecture

**Rejected because:**  
Hard to scale ML workloads separately from orchestration and execution logic.

### 5.5 Stream-Only Architecture (Kafka-first)

**Deferred:**  
Streaming improves throughput but adds operational complexity. Current design is modular enough to adopt streaming later.

---

## 6) How This Differs From SIEM and SOAR

### 6.1 Compared to Traditional SIEM

Traditional SIEM:
- Collects logs and triggers alerts based on rules.
- Heavy reliance on correlation rules and manual tuning.

This engine:
- **Normalizes alerts into an intelligence-ready schema**.
- Produces **reasoned risk scores** with evidence and confidence.
- Generates **action plans** rather than just alerting.

### 6.2 Compared to Traditional SOAR

Traditional SOAR:
- Executes predefined playbooks triggered by alert types.
- Limited adaptiveness to context or evidence quality.

This engine:
- Uses **model-driven planning** to propose actions.
- **Adapts to context** (severity, confidence, asset criticality, etc.).
- Supports **policy-driven approvals** and dynamic risk thresholds.

In short:  
SIEM = "detect and alert"  
SOAR = "execute static playbook"  
This engine = **"reason, plan, and act with model-backed evidence."**

---

## 7) Capability for Growth and Scaling

### 7.1 Technical Scaling

- **Stateless HTTP intelligence service** allows horizontal scaling.
- **Model registry** enables multi-model deployments (A/B testing, staged rollout).
- **Cache layer** reduces repeated inference for similar alerts.
- **Pluggable executors** allow new action types without engine rewrites.

### 7.2 Functional Growth

- Add more connectors (e.g., Splunk, Sentinel, Elastic).
- Expand normalization mappings and enrichment providers.
- Add reinforcement or feedback loops (planned).
- Integrate vector search for evidence retrieval.

### 7.3 Operational Maturity

- Can evolve toward:
  - Streaming ingestion (Kafka/Redis)
  - Queue-based inference workers
  - Separate GPU nodes for planners/scorers

---

## 8) Final State Summary

- Engine is **functional end-to-end** with local intelligence.
- Architecture supports **hybrid intelligence** (deterministic + LLM).
- System is structured for **incremental improvement** without breaking core flows.
