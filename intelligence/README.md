# Local Intelligence Services

This folder contains Python HTTP services for:
- **Scoring** alerts (`/v1/score`)
- **Planning** actions (`/v1/plan`)

They are designed to integrate with the C# engine’s `HttpThreatScorerClient` and `HttpPlannerClient`.

---

## Run the service

From the repo root:

```
python -m intelligence
```

Environment variables:
```
INTEL_HOST=0.0.0.0
INTEL_PORT=8080
INTEL_SCORER_MODE=hybrid
INTEL_LOCAL_MODEL=/path/to/local/model-or-hf-id
INTEL_LOCAL_ADAPTER=/path/to/adapter (optional)
INTEL_LOCAL_MAX_NEW_TOKENS=256
INTEL_LOCAL_TEMPERATURE=0.2
INTEL_OLLAMA_BASEURL=http://localhost:11434
INTEL_OLLAMA_MODEL=mistral
INTEL_OLLAMA_TIMEOUT=120
INTEL_PLANNER_MODE=local
INTEL_PLANNER_BASEURL=
INTEL_PLANNER_API_KEY=
INTEL_PLANNER_API_KEY_HEADER=Authorization
INTEL_PLANNER_API_KEY_PREFIX=Bearer
INTEL_PLANNER_TIMEOUT=60
INTEL_PLANNER_LOCAL_MODEL=
INTEL_PLANNER_LOCAL_ADAPTER=
INTEL_PLANNER_LOCAL_MAX_NEW_TOKENS=256
INTEL_PLANNER_LOCAL_TEMPERATURE=0.2
INTEL_PLANNER_OLLAMA_BASEURL=http://localhost:11434
INTEL_PLANNER_OLLAMA_MODEL=mistral
INTEL_PLANNER_OLLAMA_TIMEOUT=120
INTEL_CACHE_SIZE=256
```

Notes:
- The local model is loaded **once at startup**, not per request.
- Scorer mode can be `local`, `ollama`, or `hybrid`.
- Planner mode can be `local`, `remote`, or `hybrid`.

---

## 1) Scorer endpoint

**POST** `/v1/score`

**Request (example):**
```
{
  "correlationId": "abc123",
  "alert": {
    "sourceSiem": "wazuh",
    "alertId": "1764509831.0",
    "type": "PortScanFromIp",
    "timestampUtc": "2025-11-30T13:37:11.699Z",
    "entities": {
      "hostId": "host-1",
      "username": "user1",
      "srcIp": "10.0.0.5",
      "fileHash": "hash"
    },
    "context": {
      "environment": "dev",
      "assetCriticality": 2,
      "privileged": false
    }
  }
}
```

**Response:**
```
{
  "severity": 55,
  "confidence": 0.65,
  "hypothesis": "Possible scanning activity.",
  "evidence": ["keyword:scan"]
}
```

**Batch scoring**

**POST** `/v1/score/batch`

**Request:**
```
{
  "alerts": [
    { "type": "PortScanFromIp", "severity": 55, "entities": {"srcIp":"10.0.0.5"} },
    { "type": "BruteForceUser", "severity": 60, "entities": {"username":"bob"} }
  ]
}
```

**Response:**
```
{
  "results": [
    { "severity": 55, "confidence": 0.65, "hypothesis": "...", "evidence": ["..."] },
    { "severity": 60, "confidence": 0.70, "hypothesis": "...", "evidence": ["..."] }
  ]
}
```

---

## 2) Planner endpoint

**POST** `/v1/plan`

**Request (example):**
```
{
  "alert": {
    "sourceSiem": "wazuh",
    "alertId": "1764509831.0",
    "type": "PortScanFromIp",
    "ruleName": "Port scan detected",
    "timestampUtc": "2025-11-30T13:37:11.699Z",
    "severity": 55,
    "entities": {
      "hostId": "host-1",
      "username": "user1",
      "srcIp": "10.0.0.5",
      "fileHash": "hash"
    },
    "context": {
      "environment": "dev",
      "assetCriticality": 2,
      "privileged": false
    }
  },
  "assessment": {
    "confidence": 0.65,
    "severity": 55,
    "hypothesis": "Possible scanning activity.",
    "evidence": ["keyword:scan"],
    "recommendedActions": []
  },
  "planning": {
    "environment": "dev",
    "dryRun": true,
    "nowUtc": "2025-11-30T13:37:11.699Z"
  }
}
```

**Response (example):**
```
{
  "plan": {
    "planId": "abcd1234",
    "strategy": "Contain",
    "priority": 68,
    "summary": "Strategy=Contain, Severity=55, Confidence=0.65",
    "actions": [
      {
        "type": "BlockIp",
        "risk": 55,
        "expectedImpact": 30,
        "reversible": true,
        "parameters": { "src_ip": "10.0.0.5" },
        "rationale": "Block suspicious source IP."
      },
      {
        "type": "OpenTicket",
        "risk": 5,
        "expectedImpact": 5,
        "reversible": false,
        "parameters": {},
        "rationale": "Create a tracking ticket."
      }
    ],
    "rollbackActions": [
      {
        "type": "UnblockIp",
        "risk": 10,
        "expectedImpact": 5,
        "reversible": false,
        "parameters": { "src_ip": "10.0.0.5" },
        "rationale": "Rollback for BlockIp"
      }
    ],
    "rationale": [
      "Selected strategy Contain based on confidence 0.65 and severity 55.",
      "Asset criticality: 2; privileged identity: False."
    ],
    "tags": {
      "environment": "dev",
      "generatedAt": "2025-11-30T13:37:11.699Z"
    }
  }
}
```

---

## Notes

- The current logic is rule‑based and deterministic.
- You can replace the heuristic functions with local model inference or remote model calls.
