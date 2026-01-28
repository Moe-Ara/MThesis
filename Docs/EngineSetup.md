# Engine Setup (Human-Readable Guide)

This document explains how to run the SIEM policy engine end‑to‑end, either by polling the SIEM or via webhook notifications. It also lists the environment variables for all external integrations.

---

## 1) What the engine does

The engine’s high‑level flow is:

1. **Ingest alerts** (Wazuh API polling or webhook push)
2. **Normalize/Enrich** into a canonical `NormalizedAlert`
3. **Score** the alert using an HTTP scorer (or stub fallback)
4. **Plan** actions using an HTTP planner (or fallback planner)
5. **Apply policy rules** (now JSON‑driven)
6. **Execute** approved actions (ticket/notification/firewall)
7. **Audit** all decisions and actions to JSONL

---

## 2) Run modes

### A) Webhook mode (event‑driven)

Enable the webhook listener by setting:

```
ORCHESTRATOR_WEBHOOK_URL=http://+:8085/alerts/
```

Then POST alert JSON to that URL. Example (PowerShell):

```
Invoke-RestMethod -Method Post -Uri http://localhost:8085/alerts/ -Body $json -ContentType "application/json"
```

Notes:
- The listener expects **JSON** in the request body.
- Optional header: `X-Siem-Name` (defaults to `wazuh`).
- If `ORCHESTRATOR_WEBHOOK_URL` is set, **polling is disabled**.

### B) Polling mode

Unset `ORCHESTRATOR_WEBHOOK_URL`, and the engine will poll:

```
ORCHESTRATOR_POLL_SECONDS=30
ORCHESTRATOR_MAX_CYCLES=0
```

`ORCHESTRATOR_MAX_CYCLES=0` means infinite.

---

## 3) Wazuh API (polling)

To enable Wazuh API polling:

```
WAZUH_API_BASEURL=https://wazuh.example:55000
WAZUH_API_KEY=your_api_key
WAZUH_ALERTS_ENDPOINT=/alerts
```

Optional:
```
WAZUH_ACK_ENDPOINT=/alerts/{alertId}/ack
WAZUH_API_KEY_HEADER=Authorization
WAZUH_API_KEY_PREFIX=Bearer
WAZUH_LIMIT_PARAM=limit
WAZUH_SINCE_PARAM=from
WAZUH_CURSOR_PARAM=cursor
WAZUH_TIMEOUT_SECONDS=30
```

If `WAZUH_API_BASEURL` is not set, the engine falls back to a built‑in simulator.

---

## 4) Scorer service (HTTP)

To enable the real scorer:

```
THREAT_SCORER_BASEURL=https://scorer.example:8080
THREAT_SCORER_API_KEY=your_scorer_key
```

If not set, the engine uses a stub scorer.

---

## 5) Planner service (HTTP)

To enable the real planner:

```
PLANNER_API_BASEURL=https://planner.example:8081
PLANNER_API_KEY=your_planner_key
PLANNER_API_ENDPOINT=/v1/plan
PLANNER_API_KEY_HEADER=Authorization
PLANNER_API_KEY_PREFIX=Bearer
PLANNER_API_TIMEOUT_SECONDS=30
```

If not set, the engine uses the built‑in planner.

---

## 6) Local intelligence services (Python)

The repo includes local Python services under `intelligence/` that expose:
- `POST /v1/score`
- `POST /v1/plan`

Run them with:
```
python -m intelligence
```

Then point the C# engine to them:
```
THREAT_SCORER_BASEURL=http://localhost:8080
PLANNER_API_BASEURL=http://localhost:8080
```

### Hybrid scorer (local + Ollama fallback)

The local scorer supports hybrid mode:

```
INTEL_SCORER_MODE=hybrid
INTEL_LOCAL_MODEL=/path/to/local/model-or-hf-id
INTEL_LOCAL_ADAPTER=/path/to/adapter (optional)
INTEL_OLLAMA_BASEURL=http://localhost:11434
INTEL_OLLAMA_MODEL=mistral
```

Behavior:
- If `INTEL_LOCAL_MODEL` is set, it tries local inference first.
- If local fails or is unset, it falls back to Ollama.
- If both fail, it uses a deterministic rule‑based fallback.
- Local models are loaded once at service startup.

### Planner modes

The planner service supports local/remote/hybrid:

```
INTEL_PLANNER_MODE=local
INTEL_PLANNER_BASEURL=http://planner.example:8081
INTEL_PLANNER_API_KEY=your_key
```

Planner model options:

```
INTEL_PLANNER_LOCAL_MODEL=/path/to/model-or-hf-id
INTEL_PLANNER_LOCAL_ADAPTER=/path/to/adapter (optional)
INTEL_PLANNER_LOCAL_MAX_NEW_TOKENS=256
INTEL_PLANNER_LOCAL_TEMPERATURE=0.2
INTEL_PLANNER_OLLAMA_BASEURL=http://localhost:11434
INTEL_PLANNER_OLLAMA_MODEL=mistral
INTEL_PLANNER_OLLAMA_TIMEOUT=120
```

---

### Health check

```
GET /health
```

Returns:
- active scorer/planner class
- local model loaded status
- Ollama connectivity
- request counters
- cache size and usage

---

### Scoring cache

Enable a simple LRU‑style cache with:

```
INTEL_CACHE_SIZE=256
```

### Batch scoring

Use the batch endpoint for higher throughput:

```
POST /v1/score/batch
```

Payload:
```
{ "alerts": [ { ... }, { ... } ] }
```

---

## 6) Policy rules (JSON‑driven)

Policies are now loaded from a JSON file:

```
POLICY_CONFIG_PATH=policy_config.json
```

Example policies are located at:
- `policy_config.json` (default)
- `policy_config.example.json` (more strict example)

---

## 7) Executors (HTTP)

These are optional generic HTTP executors. If a base URL is set, the HTTP executor is used; otherwise, a stub is used.

### Ticketing
```
TICKETING_API_BASEURL=https://ticketing.example
TICKETING_API_KEY=your_ticketing_key
TICKETING_API_ENDPOINT=/v1/tickets
TICKETING_API_KEY_HEADER=Authorization
TICKETING_API_KEY_PREFIX=Bearer
TICKETING_API_TIMEOUT_SECONDS=30
```

### Notification
```
NOTIFICATION_API_BASEURL=https://notify.example
NOTIFICATION_API_KEY=your_notification_key
NOTIFICATION_API_ENDPOINT=/v1/notify
NOTIFICATION_API_KEY_HEADER=Authorization
NOTIFICATION_API_KEY_PREFIX=Bearer
NOTIFICATION_API_TIMEOUT_SECONDS=30
```

### Firewall
```
FIREWALL_API_BASEURL=https://firewall.example
FIREWALL_API_KEY=your_firewall_key
FIREWALL_API_TIMEOUT_SECONDS=30
```

---

## 8) Audit logs

The engine writes JSONL audit logs here:

```
data/audit.jsonl
```

---

## 9) Quick start

1. Copy `.env` and fill real values.
2. Build and run:
```
dotnet build NetCore/Core/Core.csproj -c Release
dotnet run --project NetCore/Core/Core.csproj
```
3. If using webhook mode, POST alerts to the webhook URL.

---

## 10) What’s still needed for production

- Confirm Wazuh alert JSON fields and adjust the mapper if needed
- Implement real integrations for ticketing/notification/firewall
- Add enrichment data sources for assets/identities/threat intel
*** End Patch"} } as any) to=functions.apply_patch? Wait tool is apply_patch freeform. I should format as patch. Let's do proper patch. 
