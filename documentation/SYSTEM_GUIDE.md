# SOAR Agent — System Guide & User Manual

## Table of Contents

1. [What the System Does](#1-what-the-system-does)
2. [Architecture Overview](#2-architecture-overview)
3. [The Full Processing Pipeline](#3-the-full-processing-pipeline)
4. [Running the System](#4-running-the-system)
5. [Operating Modes](#5-operating-modes)
6. [Intelligence Service](#6-intelligence-service)
7. [Model Registry & Profiles](#7-model-registry--profiles)
8. [Policy Engine](#8-policy-engine)
9. [Action Catalog](#9-action-catalog)
10. [SIEM Connectors](#10-siem-connectors)
11. [Configuration Reference — .env](#11-configuration-reference--env)
12. [Configuration Reference — policy_config.json](#12-configuration-reference--policy_configjson)
13. [Configuration Reference — model registry](#13-configuration-reference--model-registry)
14. [Audit Log & Case Management](#14-audit-log--case-management)
15. [Running the Demo](#15-running-the-demo)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. What the System Does

This is a **Security Orchestration, Automation and Response (SOAR) agent** — an AI-driven system that monitors security alerts from one or more SIEMs (Wazuh, Microsoft Sentinel, or any webhook-compatible source), scores them for threat severity, plans a response, enforces policy, and executes containment actions automatically — with human review only for the highest-risk operations.

The goal is to **reduce analyst workload**: routine containment actions (block an attacking IP, isolate a compromised host) execute within seconds of the alert arriving, without waiting for a human. Analysts are only looped in for actions that are irreversible or affect legitimate users (e.g., disabling a user account).

### What it does end-to-end

```
SIEM alert arrives
      │
      ▼
Normalization — extract entities, map alert type, validate
      │
      ▼
Threat Scoring — ML classifier assigns severity + confidence
      │
      ▼
Response Planning — custom neural network selects strategy + actions
      │
      ▼
Policy Evaluation — decide which actions auto-execute vs. need approval
      │
      ▼
Execution — dry-run or live: BlockIp, IsolateHost, OpenTicket, Notify, ...
      │
      ▼
Audit — every step written to data/audit.jsonl
```

---

## 2. Architecture Overview

The system has two processes that run together:

### 2.1 C# Core Engine (`NetCore/Core/`)

The orchestration layer. Handles:
- Connecting to SIEMs and pulling/receiving alerts
- Running the normalization pipeline
- Calling the intelligence service over HTTP
- Enforcing the policy engine
- Executing response actions
- Writing the audit log

Built with .NET 9. Entry point: `NetCore/Core/Program.cs`.

### 2.2 Python Intelligence Service (`intelligence/`)

A FastAPI HTTP server that runs the ML models. The C# engine calls it for every alert. Handles:
- **Scoring** (`POST /v1/score`): classifies severity and confidence using a scikit-learn TF-IDF + classifier model
- **Planning** (`POST /v1/plan`): selects response strategy and specific actions using a custom neural network (270K parameter MLP)

Entry point: `python -m intelligence` (runs `intelligence/app.py`).

### 2.3 Key Source Files

| File | Purpose |
|------|---------|
| `NetCore/Core/Program.cs` | Startup: wires all services, chooses operating mode |
| `NetCore/Core/AgentOrchestrator.cs` | Main alert processing loop |
| `NetCore/Core/Policy/PolicyEngine.cs` | Decides approve / pending / deny for each action |
| `NetCore/Core/Policy/PolicyConfig.cs` | Policy configuration loader |
| `NetCore/Core/Planning/ActionCatalogDefaults.cs` | Defines all supported actions and their risk levels |
| `NetCore/Core/Connectors/Wazuh/WazuhAlertMapper.cs` | Maps Wazuh JSON → normalized alert |
| `NetCore/Core/Connectors/Sentinel/SentinelAlertMapper.cs` | Maps Sentinel JSON → normalized alert |
| `NetCore/Core/Notification/WebhookAlertListener.cs` | HTTP listener for webhook-mode alerts |
| `intelligence/app.py` | FastAPI application with /score and /plan routes |
| `intelligence/scorers/classifier.py` | TF-IDF + ML classifier scorer |
| `intelligence/planners/custom_nn.py` | Custom neural network planner |
| `intelligence/core/model_registry.py` | Loads model profiles from registry.json |
| `.env` | All runtime configuration |
| `policy_config.json` | Policy thresholds and approval rules |
| `intelligence/models/registry.json` | Model profile definitions |

---

## 3. The Full Processing Pipeline

### Step 1 — Alert Ingestion

Depending on operating mode, alerts arrive via:
- **Pull mode**: the engine polls the Wazuh API on a schedule
- **Webhook mode**: alerts are POSTed to the engine's HTTP listener
- **Simulation mode**: synthetic alerts are generated internally

Every incoming alert becomes a `RawAlert` with fields: `AlertId`, `SiemName`, `TimestampUtc`, `AlertType`, `RuleName`, `OriginalSeverity`, `Payload` (full raw JSON).

### Step 2 — Normalization

The `NormalizationPipeline` runs three sub-steps:

1. **Mapping**: an `IAlertMapper` converts the raw JSON into a `NormalizedAlert`. Different SIEMs have different mappers:
   - `WazuhAlertMapper`: extracts `rule.groups` → maps to recognized alert type, extracts entities from Wazuh-specific JSON paths
   - `SentinelAlertMapper`: extracts from `properties.title`, `properties.entities[]`, severity strings

2. **Validation**: `BasicAlertValidator` rejects alerts missing a timestamp or alert ID.

3. **Enrichment**: optional enrichment providers can add asset criticality, identity privilege level, threat intel. Currently no providers are active by default.

The output is an `EnrichedAlert` containing the `NormalizedAlert` plus optional enrichment context.

**Recognized alert types** (what the ML models were trained on):
- `BruteForceUser` — repeated authentication failures
- `MalwareHashOnHost` — known malware hash detected on an endpoint
- `SuspiciousProcessOnHost` — anomalous process execution (Sysmon, PowerShell, etc.)
- `PortScanFromIp` — network scanning / intrusion detection
- `PhishingEmailReceived` — email-based threats

The Wazuh mapper translates Wazuh rule groups to these types:
- `authentication_failed`, `brute_force`, `sshd` → `BruteForceUser`
- `ransomware`, `malware`, `trojan` → `MalwareHashOnHost`
- `sysmon_process-anomalies`, `rootcheck`, `sudo` → `SuspiciousProcessOnHost`
- `intrusion_detection`, `network_scan`, `web` → `PortScanFromIp`
- `phishing`, `email` → `PhishingEmailReceived`

### Step 3 — Threat Scoring

The engine calls `POST /v1/score` on the intelligence service, passing the normalized alert as JSON.

The **ClassifierScorer** (`intelligence/scorers/classifier.py`):
1. Builds a text prompt from the alert fields (type, entities, raw payload)
2. Runs the prompt through a TF-IDF vectorizer → 11,168-dim feature vector
3. Passes through the scikit-learn pipeline → 5-class probability distribution: `benign`, `low`, `medium`, `high`, `critical`
4. Returns the top class as label plus a calibrated confidence score

**Confidence calibration**: Raw `max(proba)` underestimates certainty in 5-class problems (random baseline = 20%). When the top class beats the runner-up by ≥1.1x (decisive lead), a label-calibrated floor is applied:

| Predicted Label | Confidence Floor |
|-----------------|-----------------|
| critical | 0.88 |
| high | 0.72 |
| medium | 0.52 |
| low | 0.38 |
| benign | 0.22 |

The scorer also generates:
- **hypothesis**: a natural-language sentence explaining the threat (e.g., "Multiple failed authentication attempts against account 'root' (87 failed attempts) suggest brute-force activity.")
- **evidence**: up to 6 key indicators extracted from the alert (e.g., `src_ip=185.220.101.47`, `failed_logins=87`)

### Step 4 — Response Planning

The engine calls `POST /v1/plan` on the intelligence service, passing both the alert and the scoring result.

The **CustomNNPlanner** (`intelligence/planners/custom_nn.py`):
1. Extracts ~70 structured features + 128 TF-IDF text features (198 total) from the alert
2. Runs through a 512→256→128 MLP with three output heads:
   - **Strategy head** (5-class): Contain / ContainAndCollect / Investigate / Harden / NotifyOnly
   - **Action head** (multi-label): which of 8 containment actions to include
   - **Priority head** (regression): urgency 0–100
3. Applies entity-aware sanitization: only includes actions whose required parameters are available (e.g., BlockIp only if `srcIp` is present, IsolateHost only if `hostId` or `hostname` is present)
4. If confidence < 0.60, restricts to safe actions only (OpenTicket, Notify)

The planner also generates:
- **summary**: a one-line description of the response (e.g., "Contain: BlockIp, IsolateHost.")
- **rationale**: 3-item list explaining severity level, confidence impact, and strategy choice
- **per-action rationale**: why each specific action was chosen

**Available strategies**:

| Strategy | Meaning | Typical Actions |
|----------|---------|-----------------|
| Contain | Stop the active threat | BlockIp, IsolateHost, KillProcess |
| ContainAndCollect | Stop + gather forensics | BlockIp, IsolateHost, CollectForensics |
| Investigate | Gather data before acting | CollectForensics, OpenTicket |
| Harden | Preventive hardening | DisableUser, BlockIp |
| NotifyOnly | Alert analyst, no automation | Notify, OpenTicket |

### Step 5 — Policy Evaluation

The `PolicyEngine` evaluates each planned action independently. Three possible outcomes:

**Approved**: action executes immediately (or as dry-run in test mode)
**PendingApproval**: action is queued; a human must review before execution
**Denied**: action is blocked (hard rejection, e.g., missing required parameters)

The policy engine applies these checks in order:

1. **Unknown action type** → Denied
2. **Missing required parameters** → Denied
3. **Forbidden in environment** (e.g., specific actions blocked in prod) → Denied
4. **Confidence below autonomy threshold** AND action not in safe list → Denied
5. **RequiresApprovalByDefault** (per action catalog) → PendingApproval
6. **Risk ≥ riskApprovalThreshold** → PendingApproval
7. **Impact ≥ impactApprovalThreshold** → PendingApproval
8. **Production environment** + action in requireApprovalInProd list → PendingApproval
9. **Privileged identity target** → PendingApproval or Denied (depending on action)
10. **Critical asset target** → PendingApproval or Denied

Actions that pass all checks → **Approved**.

### Step 6 — Execution

The `ExecutionPipeline` runs each approved action through the appropriate executor:

| Action Type | Executor | What it does |
|-------------|---------|--------------|
| BlockIp | `FirewallExecutor` / `HttpFirewallExecutor` | Calls firewall API or logs dry-run |
| IsolateHost | `HostIsolationExecutor` | Calls host isolation API or logs dry-run |
| DisableUser | `UserAccessExecutor` | Calls identity/AD API or logs dry-run |
| KillProcess | `HostIsolationExecutor` | Calls process kill API or logs dry-run |
| QuarantineFile | `HostIsolationExecutor` | Calls file quarantine API or logs dry-run |
| OpenTicket | `TicketingExecutor` / `HttpTicketingExecutor` | Creates ticket or logs dry-run |
| Notify | `NotificationExecutor` / `HttpNotificationExecutor` | Sends notification or logs dry-run |
| CollectForensics | `HostIsolationExecutor` | Triggers forensics collection |

When `ORCHESTRATOR_DRY_RUN=true` (the default), all executors log the action without making real API calls.

### Step 7 — Audit

Every step writes a structured JSON entry to `data/audit.jsonl`. Key event types:
- `AlertProcessed`: final summary with approved/pending/denied counts
- `ActionResult`: outcome of each individual action execution
- `ExecutionStart` / `ExecutionEnd`: execution pipeline boundaries
- `PlanningFailed`, `NormalizationFailed`, `PolicyFailed`: error events

---

## 4. Running the System

### Prerequisites

- .NET 9 SDK
- Python 3.10+ with dependencies from `pyproject.toml`
- (Optional) Ollama if using LLM-based scoring/planning

### Starting the Intelligence Service

The Python intelligence service must be running before or alongside the engine. It starts automatically when the engine starts (via `IntelligenceProcessManager`), but you can also start it manually:

```bash
# From the project root
python -m intelligence
```

The service listens on `http://0.0.0.0:8080` by default. Check it's healthy:

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{
  "ok": true,
  "scorer": "ClassifierScorer",
  "planner": "CustomNNPlanner",
  "active_profile": "custom-nn-reasoning-20260306",
  ...
}
```

### Starting the Engine

```bash
# From the project root
cd NetCore/Core
dotnet run
```

Or with a specific environment variable override:

```bash
ORCHESTRATOR_WEBHOOK_URL=http://localhost:5050/ dotnet run --project NetCore/Core
```

The engine reads all configuration from `.env` in the project root (it searches upward from the binary directory).

---

## 5. Operating Modes

The engine operates in one of three modes, determined by which environment variables are set:

### Mode 1 — Simulation (default, no SIEM configured)

**When**: `WAZUH_API_BASEURL` is empty AND `ORCHESTRATOR_WEBHOOK_URL` is empty.

**Behavior**: generates synthetic alerts internally using `ThreatGenerator`. Useful for development and testing without any real SIEM.

**Relevant settings**:
```
SIMULATOR_ALERT_COUNT=6           # How many synthetic alerts to generate
SIMULATOR_INCLUDE_EDGE_CASES=true # Include tricky/ambiguous scenarios
SIMULATOR_FORCE_SCENARIO=         # Force a specific scenario (e.g., BruteForceUser)
ORCHESTRATOR_MAX_CYCLES=1         # Run once (0 = loop forever)
ORCHESTRATOR_POLL_SECONDS=0       # Seconds between cycles (0 = no polling loop)
```

**To run once with simulation**:
```bash
dotnet run --project NetCore/Core
```

### Mode 2 — Wazuh Pull Mode

**When**: `WAZUH_API_BASEURL` is set to a real Wazuh API URL.

**Behavior**: the engine polls the Wazuh API on a schedule, pulling new alerts, processing them, and acknowledging them.

**Relevant settings**:
```
WAZUH_API_BASEURL=https://your-wazuh-host:55000
WAZUH_API_KEY=your_api_key_here
ORCHESTRATOR_POLL_SECONDS=30      # How often to poll (seconds)
ORCHESTRATOR_MAX_CYCLES=0         # 0 = run forever
```

### Mode 3 — Webhook Mode (recommended for multi-SIEM)

**When**: `ORCHESTRATOR_WEBHOOK_URL` is set (e.g., `http://localhost:5050/`).

**Behavior**: the engine starts an HTTP listener. Any system can POST alerts to this URL. The `X-Siem-Name` header tells the engine which mapper to use.

**Supported SIEM names** (via `X-Siem-Name` header):
- `wazuh` → WazuhAlertMapper
- `sentinel` or `microsoft-sentinel` or `azure-sentinel` → SentinelAlertMapper

**Example**:
```bash
curl -X POST http://localhost:5050/ \
  -H "Content-Type: application/json" \
  -H "X-Siem-Name: wazuh" \
  -d @alert.json
```

**To start in webhook mode**:
```bash
ORCHESTRATOR_WEBHOOK_URL=http://localhost:5050/ dotnet run --project NetCore/Core
```

---

## 6. Intelligence Service

The Python service exposes three endpoints:

### `GET /health`

Returns status of all components. Check this to confirm the right models are loaded.

```json
{
  "ok": true,
  "scorer": "ClassifierScorer",
  "planner": "CustomNNPlanner",
  "active_profile": "custom-nn-reasoning-20260306",
  "score_requests": 42,
  "plan_requests": 42,
  "cache_size": 256,
  "cache_items": 15
}
```

### `POST /v1/score`

Accepts a normalized alert JSON. Returns severity, confidence, hypothesis, evidence.

```json
{
  "severity": 71,
  "confidence": 0.72,
  "hypothesis": "Multiple failed authentication attempts against account 'root' (87 failed attempts) suggest brute-force activity.",
  "evidence": ["alert_type=BruteForceUser", "src_ip=185.220.101.47", "user=root", "failed_logins=87"]
}
```

### `POST /v1/plan`

Accepts `{"alert": ..., "assessment": ...}`. Returns a full response plan.

```json
{
  "plan": {
    "strategy": "Contain",
    "priority": 85,
    "summary": "Contain: BlockIp.",
    "rationale": ["High severity (71/100)...", "Moderate confidence (72%)...", "Active containment..."],
    "actions": [
      {"type": "BlockIp", "parameters": {"src_ip": "185.220.101.47"}, "rationale": "Block the source IP..."},
      {"type": "OpenTicket", "parameters": {}, "rationale": "Create an auditable record..."}
    ],
    "rollbackActions": [
      {"type": "UnblockIp", "parameters": {"src_ip": "185.220.101.47"}}
    ]
  }
}
```

### Scorer Modes (`INTEL_SCORER_MODE`)

| Mode | Class | Description |
|------|-------|-------------|
| `classifier` | `ClassifierScorer` | Fast, offline, TF-IDF + ML (default) |
| `local` | `LocalModelScorer` | HuggingFace model loaded locally |
| `ollama` | `OllamaScorer` | LLM via Ollama (requires Ollama running) |
| `calibrated` | `CalibratedScorer` | Classifier for severity + LLM for rationale |

### Planner Modes (`INTEL_PLANNER_MODE`)

| Mode | Class | Description |
|------|-------|-------------|
| `custom_nn` | `CustomNNPlanner` | Custom 270K-param MLP (default) |
| `seq2seq` | `Seq2SeqPlanner` | Fine-tuned flan-t5-base (250M params) |
| `local` | `LocalModelPlanner` | HuggingFace model loaded locally |
| `ollama` | `OllamaPlanner` | LLM via Ollama |
| `rule` | `RulePlanner` | Deterministic rule-based fallback |
| `remote` | `RemotePlanner` | External HTTP planner API |

---

## 7. Model Registry & Profiles

File: `intelligence/models/registry.json`

The model registry defines named **profiles**, each specifying which scorer and planner to use. This allows switching the entire intelligence stack without changing code.

### Active Profile

Set by `INTEL_ACTIVE_PROFILE` in `.env` (overrides `registry.json`'s `"active"` field).

```
INTEL_ACTIVE_PROFILE=custom-nn-reasoning-20260306
```

### Current Profiles

| Profile | Scorer | Planner | Notes |
|---------|--------|---------|-------|
| `custom-nn-reasoning-20260306` | classifier | custom_nn (planner_nn_reasoning_20260306) | **Default, production-ready** |
| `custom-nn` | classifier | custom_nn (planner_nn) | Earlier NN model |
| `custom` | classifier | seq2seq (planner_seq2seq) | flan-t5-base planner |
| `seq2seq-compact` | classifier | seq2seq (planner_seq2seq_compact) | Smaller seq2seq |
| `foundation-sec` | calibrated | ollama (foundation-sec-planner) | LLM-based (requires Ollama) |
| `baron-security` | ollama | ollama | Fully LLM-based (requires Ollama) |

### Switching Profiles

To switch to the LLM-based baron-security profile:
```
INTEL_ACTIVE_PROFILE=baron-security
INTEL_OLLAMA_MODEL=baron-security
INTEL_PLANNER_OLLAMA_MODEL=baron-security
```

### Model Files

Located in `intelligence/models/`:
- `scorer_classifier/` — TF-IDF + classifier (model.joblib, meta.json)
- `planner_nn_reasoning_20260306/` — Custom NN planner (model.pt, meta.json, tfidf.pkl)
- `planner_nn/` — Earlier NN planner
- `planner_seq2seq/` — flan-t5-base planner

### Response Caching

The intelligence service caches scorer and planner responses in an LRU cache. Size is controlled by `INTEL_CACHE_SIZE` (default 256). The cache is cleared when the service restarts.

---

## 8. Policy Engine

File: `NetCore/Core/Policy/PolicyEngine.cs`
Config: `policy_config.json`

The policy engine is the governance layer that decides which AI-planned actions are safe to execute automatically versus which require human review.

### Decision Outcomes

| Status | Meaning | What happens |
|--------|---------|--------------|
| **Approved** | Safe to execute autonomously | Action runs immediately (dry-run in test mode) |
| **PendingApproval** | Needs human sign-off | Action queued in ApprovalWorkflow; not executed until approved |
| **Denied** | Hard block | Action never executes; logged in audit |

### Decision Logic

For each action in the plan, the policy engine evaluates in this order:

**Hard denials** (→ Denied, no override possible):
1. Action type not in the catalog
2. Required parameters missing from the plan
3. Action explicitly forbidden in the current environment

**Soft gating** (→ PendingApproval):
4. `RequiresApprovalByDefault = true` in the action catalog
5. Plan's action risk ≥ `riskApprovalThreshold`
6. Plan's action impact ≥ `impactApprovalThreshold`
7. Running in production environment AND action is in `requireApprovalInProd`
8. Target identity is privileged AND action is in `requireApprovalOnPrivilegedIdentities`
9. Target asset criticality ≥ `criticalAssetThreshold` AND action is in `requireApprovalOnCriticalAssets`

**Auto-approve** (→ Approved): everything that passes all the above checks.

### Low-Confidence Override

When scorer confidence is below `minConfidenceForAutonomy`, actions **not** in `safeLowConfidenceActions` are denied. This prevents risky containment actions from executing when the scorer is uncertain.

Currently:
- `minConfidenceForAutonomy = 0.60`
- `safeLowConfidenceActions = [OpenTicket, Notify]`

So at confidence < 0.60, only OpenTicket and Notify are allowed; all containment actions are denied.

---

## 9. Action Catalog

File: `NetCore/Core/Planning/ActionCatalogDefaults.cs`

Defines every action the system can take, its risk level, and whether it requires approval by default.

| Action | Requires Approval by Default | Risk | Impact | Reversible | Required Params |
|--------|------------------------------|------|--------|-----------|-----------------|
| BlockIp | No | 55 | 30 | Yes (UnblockIp) | src_ip |
| UnblockIp | No | 10 | 5 | No | src_ip |
| IsolateHost | No | 70 | 60 | Yes (UnisolateHost) | hostname OR host_id |
| UnisolateHost | No | 15 | 10 | No | hostname OR host_id |
| DisableUser | **Yes** | 65 | 50 | Yes (EnableUser) | username OR user_id |
| EnableUser | No | 15 | 10 | No | username OR user_id |
| KillProcess | **Yes** | 85 | 85 | No | hostId + hostname + processName + pid |
| QuarantineFile | **Yes** | 85 | 85 | No | hostId + fileHash + filePath |
| OpenTicket | No | 5 | 5 | No | none |
| Notify | No | 5 | 5 | No | none |
| CollectForensics | No | 35 | 20 | No | none |

With the current `riskApprovalThreshold = 90`, actions with risk < 90 pass the risk check. The only remaining approval gates are `RequiresApprovalByDefault` (DisableUser, KillProcess, QuarantineFile) and the `requireApprovalInProd` list.

**To make an action always require approval**: set `RequiresApprovalByDefault = true` in `ActionCatalogDefaults.cs` and rebuild.

**To raise or lower which risk levels require approval**: change `riskApprovalThreshold` in `policy_config.json` (no rebuild needed).

---

## 10. SIEM Connectors

### Wazuh (Pull Mode)

File: `NetCore/Core/Connectors/Wazuh/WazuhSiemConnector.cs`
Mapper: `NetCore/Core/Connectors/Wazuh/WazuhAlertMapper.cs`

Polls the Wazuh API for new alerts. The mapper:
- Translates `rule.groups` → one of the 5 recognized alert types
- Extracts entities from Wazuh-specific JSON paths:
  - `data.srcip`, `data.src_ip`, `agent.ip` → `srcIp`
  - `agent.name`, `agent.hostname` → `hostname`
  - `agent.id` → `hostId`
  - `data.user`, `data.srcuser` → `username`
  - `data.process_name`, `data.win.eventdata.image` → `processName`
  - `data.win.eventdata.user` → `username` (Sysmon events)
  - `data.file_hash`, `data.sha256`, `data.md5` → `fileHash`
- Maps Wazuh rule level (0–15) → normalized severity (0–100)

### Microsoft Sentinel (Webhook Mode)

File: `NetCore/Core/Connectors/Sentinel/SentinelAlertMapper.cs`

Handles two Sentinel formats:
1. **Incident format**: `properties.title`, `properties.severity` string, `properties.entities[]` array with `kind`/`properties` per entity
2. **Flat SecurityAlert format**: `AlertDisplayName`, `ExtendedProperties`

Severity mapping: `Critical`→95, `High`→80, `Medium`→55, `Low`→30, `Informational`→15

### Adding a New SIEM

1. Create `NetCore/Core/Connectors/YourSiem/YourSiemAlertMapper.cs` implementing `IAlertMapper`
2. Register it in `NetCore/Core/Connectors/MultiSiemMappingRegistry.cs`
3. Rebuild

---

## 11. Configuration Reference — `.env`

All runtime settings live in `.env` at the project root. The engine searches upward from its working directory to find this file. **Restart the engine after any change.**

### Wazuh API (Pull Mode)

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_API_BASEURL` | *(empty)* | Base URL of the Wazuh API (e.g., `https://wazuh-host:55000`). Leave empty to use simulation mode. |
| `WAZUH_API_KEY` | — | API key for Wazuh authentication |
| `WAZUH_API_KEY_HEADER` | `Authorization` | HTTP header name for the API key |
| `WAZUH_API_KEY_PREFIX` | `Bearer` | Prefix before the key value (e.g., `Bearer mykey`) |
| `WAZUH_ALERTS_ENDPOINT` | `/alerts` | Endpoint path for fetching alerts |
| `WAZUH_ACK_ENDPOINT` | `/alerts/{alertId}/ack` | Endpoint path for acknowledging alerts |
| `WAZUH_LIMIT_PARAM` | `limit` | Query param name for pagination limit |
| `WAZUH_SINCE_PARAM` | `from` | Query param name for timestamp filter |
| `WAZUH_CURSOR_PARAM` | `cursor` | Query param name for cursor-based pagination |
| `WAZUH_TIMEOUT_SECONDS` | `30` | HTTP timeout for Wazuh API calls |

### Orchestrator

| Variable | Default | Description |
|----------|---------|-------------|
| `ORCHESTRATOR_WEBHOOK_URL` | *(empty)* | If set, starts webhook listener on this URL (e.g., `http://localhost:5050/`). Overrides pull mode. |
| `ORCHESTRATOR_POLL_SECONDS` | `0` | Seconds between alert polling cycles. `0` = run once and stop. |
| `ORCHESTRATOR_MAX_CYCLES` | `1` | Maximum number of cycles before stopping. `0` = run forever. |
| `ORCHESTRATOR_DRY_RUN` | `true` | If `true`, no real API calls are made — actions are simulated and logged only. **Set to `false` for live execution.** |
| `ORCHESTRATOR_STOP_ON_FAILURE` | `false` | Stop the engine if any alert processing fails. |
| `ORCHESTRATOR_ACTION_TIMEOUT_SECONDS` | `2` | Timeout for each action executor call. |

### Threat Scorer (C# → Python)

| Variable | Default | Description |
|----------|---------|-------------|
| `THREAT_SCORER_BASEURL` | `http://localhost:8080` | Base URL of the intelligence service for scoring. Auto-set to the local service if left empty. |
| `THREAT_SCORER_API_KEY` | *(empty)* | API key for external scorer (if not using local service) |

### Planner (C# → Python)

| Variable | Default | Description |
|----------|---------|-------------|
| `PLANNER_API_BASEURL` | `http://localhost:8080` | Base URL of the intelligence service for planning. Auto-set to the local service if left empty. |
| `PLANNER_API_KEY` | *(empty)* | API key for external planner |
| `PLANNER_API_ENDPOINT` | `/v1/plan` | Endpoint path for planning requests |
| `PLANNER_API_TIMEOUT_SECONDS` | `30` | HTTP timeout for planner calls |

### Policy

| Variable | Default | Description |
|----------|---------|-------------|
| `POLICY_CONFIG_PATH` | `policy_config.json` | Path to the policy configuration file. Relative to the engine's working directory. |

### External Executors (optional)

When these are set to real URLs, the engine calls external APIs. If set to placeholder URLs containing the word "example", they are treated as unset.

| Variable | Description |
|----------|-------------|
| `TICKETING_API_BASEURL` | URL for your ticketing system (Jira, ServiceNow, etc.) |
| `TICKETING_API_KEY` | API key for the ticketing system |
| `TICKETING_API_ENDPOINT` | Endpoint path (default `/v1/tickets`) |
| `NOTIFICATION_API_BASEURL` | URL for your notification system (Slack, Teams, PagerDuty, etc.) |
| `NOTIFICATION_API_KEY` | API key for notifications |
| `NOTIFICATION_API_ENDPOINT` | Endpoint path (default `/v1/notify`) |
| `FIREWALL_API_BASEURL` | URL for your firewall/network API |
| `FIREWALL_API_KEY` | API key for the firewall |
| `FIREWALL_API_TIMEOUT_SECONDS` | Timeout for firewall calls (default `30`) |

### Case Management

| Variable | Default | Description |
|----------|---------|-------------|
| `CASE_DB_ENABLE` | `false` | Enable SQLite case database |
| `CASE_DB_PATH` | `data/cases.db` | Path to SQLite database file |

### Simulation Mode

| Variable | Default | Description |
|----------|---------|-------------|
| `SIMULATOR_ALERT_COUNT` | `6` | Number of synthetic alerts to generate per cycle |
| `SIMULATOR_INCLUDE_EDGE_CASES` | `true` | Include low-confidence and ambiguous scenarios |
| `SIMULATOR_FORCE_SCENARIO` | *(empty)* | Force a specific scenario type (e.g., `BruteForceUser`, `MalwareHashOnHost`) |

### Demo Trace

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMO_TRACE_PATH` | *(empty)* | If set, writes a single JSON file with the full trace of the last alert |
| `DEMO_TRACE_JSONL_PATH` | *(empty)* | If set, appends each alert trace as a JSONL entry |
| `DEMO_TRACE_ONLY_SUCCESS` | `false` | Only write traces for successfully processed alerts |
| `DEMO_TRACE_MAX_AUDIT` | `50` | Maximum audit entries to include in the trace |

### Intelligence Service — General

| Variable | Default | Description |
|----------|---------|-------------|
| `INTEL_HOST` | `0.0.0.0` | Host address the intelligence service binds to |
| `INTEL_PORT` | `8080` | Port the intelligence service listens on |
| `INTEL_CACHE_SIZE` | `256` | LRU cache size for scorer and planner responses |
| `INTEL_MODEL_REGISTRY` | `intelligence/models/registry.json` | Path to the model registry file |
| `INTEL_ACTIVE_PROFILE` | `custom-nn-reasoning-20260306` | Active model profile name (overrides registry's `"active"` field) |

### Intelligence Service — Scorer

| Variable | Default | Description |
|----------|---------|-------------|
| `INTEL_SCORER_MODE` | `classifier` | Scorer backend: `classifier`, `local`, `ollama`, `calibrated` |
| `INTEL_SCORER_CLASSIFIER_PATH` | `intelligence/models/scorer_classifier` | Path to the classifier model directory |
| `INTEL_SCORER_CLASSIFIER_META` | *(empty)* | Optional explicit path to the classifier's meta.json |

### Intelligence Service — Local Model Scorer

| Variable | Default | Description |
|----------|---------|-------------|
| `INTEL_LOCAL_MODEL` | *(empty)* | Path to a local HuggingFace model for scoring |
| `INTEL_LOCAL_ADAPTER` | *(empty)* | Path to a LoRA adapter for the local scorer model |
| `INTEL_LOCAL_MAX_NEW_TOKENS` | `256` | Maximum tokens the local scorer can generate |
| `INTEL_LOCAL_TEMPERATURE` | `0.2` | Sampling temperature for local scorer |

### Intelligence Service — Ollama Scorer

| Variable | Default | Description |
|----------|---------|-------------|
| `INTEL_OLLAMA_BASEURL` | `http://localhost:11434` | Ollama server URL |
| `INTEL_OLLAMA_MODEL` | `baron-security` | Model name in Ollama to use for scoring |
| `INTEL_OLLAMA_TIMEOUT` | `120` | Request timeout in seconds |
| `INTEL_OLLAMA_TEMPERATURE` | `0.1` | Sampling temperature (lower = more deterministic) |
| `INTEL_OLLAMA_TOP_P` | `0.9` | Nucleus sampling threshold |
| `INTEL_OLLAMA_REPEAT_PENALTY` | `1.05` | Penalty for repeating tokens |
| `INTEL_OLLAMA_NUM_PREDICT` | `256` | Maximum tokens to generate |
| `INTEL_OLLAMA_JSON_MODE` | `true` | Force JSON output format |

### Intelligence Service — Planner

| Variable | Default | Description |
|----------|---------|-------------|
| `INTEL_PLANNER_MODE` | `custom_nn` | Planner backend: `custom_nn`, `seq2seq`, `local`, `ollama`, `rule`, `remote` |

### Intelligence Service — Custom NN Planner

The custom NN planner's model path is set via the model registry profile. No additional env vars needed.

### Intelligence Service — Seq2Seq Planner

| Variable | Default | Description |
|----------|---------|-------------|
| `INTEL_PLANNER_SEQ2SEQ_MODEL` | *(empty)* | Path to the seq2seq model directory |
| `INTEL_PLANNER_SEQ2SEQ_MAX_NEW_TOKENS` | `384` | Max tokens to generate |
| `INTEL_PLANNER_SEQ2SEQ_NUM_BEAMS` | `4` | Beam search width |
| `INTEL_PLANNER_SEQ2SEQ_TEMPERATURE` | `0.0` | Temperature (0 = greedy) |
| `INTEL_PLANNER_SEQ2SEQ_MAX_SOURCE_LENGTH` | `1024` | Max input token length |

### Intelligence Service — Ollama Planner

| Variable | Default | Description |
|----------|---------|-------------|
| `INTEL_PLANNER_OLLAMA_BASEURL` | `http://localhost:11434` | Ollama server URL |
| `INTEL_PLANNER_OLLAMA_MODEL` | `baron-security` | Model name for planning |
| `INTEL_PLANNER_OLLAMA_TIMEOUT` | `120` | Request timeout in seconds |
| `INTEL_PLANNER_OLLAMA_TEMPERATURE` | `0.05` | Temperature (lower = more deterministic for planning) |
| `INTEL_PLANNER_OLLAMA_NUM_PREDICT` | `512` | Max tokens to generate (plans need more than scoring) |
| `INTEL_PLANNER_OLLAMA_JSON_MODE` | `true` | Force JSON output |

---

## 12. Configuration Reference — `policy_config.json`

File: `policy_config.json` (project root)

**No rebuild required** — the policy engine reads this file at startup. Restart the engine to apply changes.

```json
{
  "minConfidenceForAutonomy": 0.6,
  "riskApprovalThreshold": 90,
  "impactApprovalThreshold": 90,
  "maxActionsPerPlan": 6,
  "criticalAssetThreshold": 4,
  "safeLowConfidenceActions": ["OpenTicket", "Notify"],
  "requireApprovalInProd": ["DisableUser", "IsolateHost", "QuarantineFile", "KillProcess"],
  "requireApprovalOnPrivilegedIdentities": ["DisableUser"],
  "requireApprovalOnCriticalAssets": ["IsolateHost", "DisableUser"],
  "forbidActionsOnPrivilegedIdentities": ["DisableUser"],
  "forbidActionsOnCriticalAssets": ["KillProcess", "QuarantineFile"],
  "forbiddenActionsByEnvironment": {
    "prod": []
  }
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `minConfidenceForAutonomy` | float (0–1) | Minimum scorer confidence required for containment actions. Below this, only actions in `safeLowConfidenceActions` are allowed. **Raise to be more conservative; lower to allow more automation at uncertain alerts.** |
| `riskApprovalThreshold` | int (0–100) | Actions whose risk score (from the plan) meets or exceeds this value require human approval. Currently 90, meaning only the highest-risk actions (KillProcess, QuarantineFile at risk=85) still require approval. **Lower to require more approvals; raise to allow more automation.** |
| `impactApprovalThreshold` | int (0–100) | Same as above but for operational impact score. |
| `maxActionsPerPlan` | int | Hard cap on the number of actions per plan. Plans exceeding this are fully denied. |
| `criticalAssetThreshold` | int (1–5) | Asset criticality level (from enrichment) at or above which extra approval rules apply. |
| `safeLowConfidenceActions` | string[] | Action types that are always allowed even when confidence is below `minConfidenceForAutonomy`. |
| `requireApprovalInProd` | string[] | Action types that always require human approval when the environment is `prod`. Has no effect in `dev` mode. |
| `requireApprovalOnPrivilegedIdentities` | string[] | Action types requiring approval when the alert target is a privileged identity (requires enrichment). |
| `requireApprovalOnCriticalAssets` | string[] | Action types requiring approval when the target asset has criticality ≥ `criticalAssetThreshold`. |
| `forbidActionsOnPrivilegedIdentities` | string[] | Action types that are **hard-blocked** (Denied) when the target is a privileged identity. |
| `forbidActionsOnCriticalAssets` | string[] | Action types that are **hard-blocked** when the target asset is critical. |
| `forbiddenActionsByEnvironment` | object | Map of environment name → list of action types to hard-block in that environment. |

### Common Policy Adjustments

**Make the system more autonomous** (fewer pending actions):
- Lower `riskApprovalThreshold` to 95 or remove items from `requireApprovalInProd`
- Lower `minConfidenceForAutonomy` to 0.45

**Make the system more conservative** (more pending actions):
- Lower `riskApprovalThreshold` to 60–70
- Add actions to `requireApprovalInProd`
- Raise `minConfidenceForAutonomy` to 0.75

**Block an action entirely in production**:
- Add it to `forbiddenActionsByEnvironment["prod"]`

---

## 13. Configuration Reference — Model Registry

File: `intelligence/models/registry.json`

Defines model profiles. Add a new profile by adding an entry under `"profiles"`. Set `INTEL_ACTIVE_PROFILE` in `.env` to switch profiles without editing the registry.

### Profile Schema

```json
{
  "profiles": {
    "my-profile": {
      "scorer": {
        "type": "classifier",
        "model_path": "scorer_classifier"
      },
      "planner": {
        "type": "custom_nn",
        "model_path": "planner_nn"
      }
    }
  }
}
```

### Scorer Types in Registry

| Type | Required Fields | Description |
|------|----------------|-------------|
| `classifier` | `model_path` | scikit-learn classifier |
| `calibrated` | `confidence_floor`, `confidence_ceiling`, `classifier`, `explainer` | Classifier + LLM for rationale |
| `ollama` | `base_url`, `model` | Ollama LLM |
| `local` | `model_path` | Local HuggingFace model |

### Planner Types in Registry

| Type | Required Fields | Description |
|------|----------------|-------------|
| `custom_nn` | `model_path` | Custom MLP neural network |
| `seq2seq` | `model_path`, `max_new_tokens`, `num_beams` | Seq2seq (flan-t5) model |
| `ollama` | `base_url`, `model` | Ollama LLM |
| `local` | `model_path` | Local HuggingFace model |
| `rule` | none | Deterministic rule-based planner |

---

## 14. Audit Log & Case Management

### Audit Log

File: `data/audit.jsonl`

Every alert processing step appends a JSON entry. Each entry has:

```json
{
  "entryId": "...",
  "timestampUtc": "2026-03-07T08:14:22Z",
  "correlationId": "968728bc...",
  "component": "Orchestrator",
  "eventType": "AlertProcessed",
  "message": "Alert demo-brute-001 processed.",
  "data": {
    "alertId": "demo-brute-001",
    "siem": "wazuh",
    "approved": "3",
    "pending": "0",
    "denied": "0"
  }
}
```

**Key event types**:

| Event | Component | Description |
|-------|-----------|-------------|
| `AlertProcessed` | Orchestrator | Final summary: approved/pending/denied counts |
| `ActionResult` | Execution | Outcome of a single action (DryRun, Succeeded, Failed, Skipped) |
| `ExecutionStart` / `ExecutionEnd` | Execution | Execution pipeline boundaries with totals |
| `NormalizationFailed` | Normalization | Alert rejected during normalization |
| `PlanningFailed` | Orchestrator | Planning step threw an exception |
| `PolicyFailed` | Orchestrator | Policy evaluation threw an exception |

The `correlationId` ties all events for a single alert together — use it to trace the full lifecycle of an alert through the log.

### Reading the Audit Log

```python
import json

with open("data/audit.jsonl") as f:
    for line in f:
        event = json.loads(line)
        if event["eventType"] == "AlertProcessed":
            d = event["data"]
            print(f"{d['alertId']}: approved={d['approved']} pending={d['pending']} denied={d['denied']}")
```

### Case Management

When `CASE_DB_ENABLE=true`, each processed alert creates or updates a case in the SQLite database at `CASE_DB_PATH`. Cases aggregate the assessment, plan, and policy decision for later review.

---

## 15. Running the Demo

### Prerequisites

1. Intelligence service running: `python -m intelligence`
2. Engine binary built: `dotnet build NetCore/Core`

### Demo: Simulation Mode (no SIEM needed)

```bash
# Uses synthetic alerts
dotnet run --project NetCore/Core
```

Check `data/audit.jsonl` for results.

### Demo: Real Wazuh Alerts via Webhook

**Step 1**: Start the engine in webhook mode
```bash
ORCHESTRATOR_WEBHOOK_URL=http://localhost:5050/ dotnet run --project NetCore/Core --no-build
```

**Step 2**: Replay production-style Wazuh alerts
```bash
python scripts/replay_alerts.py --siem wazuh-rich
```

This sends 3 realistic Wazuh alerts (BruteForce SSH, Malware Hash, Suspicious PowerShell) and shows what the engine does with each.

### Demo: Multi-SIEM (Wazuh + Sentinel)

```bash
python scripts/replay_alerts.py --siem all --delay 1.5
```

Sends Wazuh archive alerts, production-style Wazuh alerts, and synthetic Sentinel incidents.

### Replay Script Options

```bash
python scripts/replay_alerts.py \
  --siem wazuh-rich   # wazuh | sentinel | all | wazuh-rich
  --limit 10          # max alerts from archive (wazuh mode)
  --delay 1.5         # seconds between alerts
  --webhook http://localhost:5050/  # override webhook URL
```

### Expected Output

After processing, check the audit:

```bash
python -c "
import json
with open('data/audit.jsonl') as f:
    for line in f:
        e = json.loads(line)
        if 'AlertProcess' in e.get('eventType',''):
            d = e['data']
            print(d['alertId'], 'approved:', d['approved'], 'pending:', d['pending'])
"
```

Expected for the 3 Wazuh-rich alerts (with default settings):
- `demo-brute-001`: approved=3, pending=0 — BlockIp + IsolateHost + Notify auto-executed
- `demo-malware-001`: approved=2+, pending=0+ — quarantine actions executed
- `demo-proc-001`: approved=2, pending=0 — IsolateHost + OpenTicket executed

---

## 16. Troubleshooting

### Intelligence service doesn't start

Check Python environment:
```bash
python -m intelligence
# Should print: INFO: Uvicorn running on http://0.0.0.0:8080
```

If models are missing, check `intelligence/models/` for `scorer_classifier/model.joblib` and `planner_nn_reasoning_20260306/model.pt`.

### Engine shows "OllamaScorer" or "OllamaPlanner" in health

The `.env` has `INTEL_SCORER_MODE=ollama` or `INTEL_PLANNER_MODE=ollama`. Change to:
```
INTEL_SCORER_MODE=classifier
INTEL_PLANNER_MODE=custom_nn
```
Restart the intelligence service.

### All alerts get NotifyOnly / confidence is low

The scorer confidence is below `minConfidenceForAutonomy` (0.60). Check the scorer output:
```bash
curl -s http://localhost:8080/health | python -c "import json,sys; d=json.load(sys.stdin); print('scorer:', d['scorer'], 'planner:', d['planner'])"
```

For the TF-IDF classifier, confidence can be low when the alert type is ambiguous (e.g., `SuspiciousProcessOnHost` — PowerShell appears in both benign and malicious training data). The calibrated confidence floor (in `intelligence/scorers/classifier.py`) handles this by applying a minimum confidence when the top predicted class has a decisive lead over the runner-up (ratio ≥ 1.1x).

### Engine can't find policy_config.json

The `POLICY_CONFIG_PATH=policy_config.json` is a relative path. The engine resolves it from its working directory. When running with `dotnet run --project NetCore/Core` from the project root, the working directory is the project root and the file is found. If you run the compiled binary from another directory, use an absolute path:
```
POLICY_CONFIG_PATH=/absolute/path/to/policy_config.json
```

### Port 5050 already in use

A previous engine instance is still running. Kill it:
```bash
powershell -Command "Stop-Process -Name Core -Force -ErrorAction SilentlyContinue"
```

### Actions are still pending after changing policy

Check that:
1. The policy config change was saved correctly
2. The engine was restarted after the config change (config is read at startup)
3. The action catalog change (if any) required a rebuild: `dotnet build NetCore/Core`

### How to verify what the policy engine is doing

Look for `ActionResult` entries in the audit log — they show the status (DryRun, Skipped, Failed) for each action. Cross-reference with the `AlertProcessed` entry's `approved`/`pending`/`denied` counts.
