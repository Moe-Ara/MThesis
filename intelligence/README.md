# Local Intelligence Services

This folder contains Python HTTP services for:
- Scoring alerts (/v1/score)
- Planning actions (/v1/plan)

They are designed to integrate with the C# engine's HttpThreatScorerClient and HttpPlannerClient.

## Run the service

From the repo root:

```
python -m intelligence
```

## BaronLLM GGUF (Ollama)

1) Download the model:
```
powershell -ExecutionPolicy Bypass -File intelligence/models/download_baronllm.ps1
```

2) Create an Ollama model:
```
powershell -ExecutionPolicy Bypass -File intelligence/ollama/create_baronllm.ps1
```

3) Point the scorer/planner to Ollama:
```
INTEL_OLLAMA_MODEL=baronllm-q6k
INTEL_PLANNER_OLLAMA_MODEL=baronllm-q6k
```

## BaronLLM GGUF (llama-cpp-python)

Install the Python bindings:
```
pip install llama-cpp-python
```

Run a local chat:
```
python intelligence/models/run_baronllm_chat.py --prompt "What is the capital of France?"
```

If the repo is gated, make sure you have logged in with:
```
huggingface-cli login
```

Environment variables:
```
INTEL_HOST=0.0.0.0
INTEL_PORT=8080
INTEL_MODEL_REGISTRY=intelligence/models/registry.json
INTEL_ACTIVE_PROFILE=foundation-sec
INTEL_SCORER_MODE=hybrid
INTEL_LOCAL_MODEL=/path/to/local/model-or-hf-id
INTEL_LOCAL_ADAPTER=/path/to/adapter (optional)
INTEL_LOCAL_MAX_NEW_TOKENS=256
INTEL_LOCAL_TEMPERATURE=0.2
INTEL_OLLAMA_BASEURL=http://localhost:11434
INTEL_OLLAMA_MODEL=mistral
INTEL_OLLAMA_TIMEOUT=120
INTEL_OLLAMA_TEMPERATURE=0.1
INTEL_OLLAMA_TOP_P=0.9
INTEL_OLLAMA_REPEAT_PENALTY=1.05
INTEL_OLLAMA_NUM_PREDICT=256
INTEL_OLLAMA_JSON_MODE=true
INTEL_SCORER_CLASSIFIER_PATH=intelligence/models/scorer_classifier
INTEL_SCORER_CLASSIFIER_META=intelligence/models/scorer_classifier/meta.json
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
INTEL_PLANNER_OLLAMA_TEMPERATURE=0.05
INTEL_PLANNER_OLLAMA_TOP_P=0.9
INTEL_PLANNER_OLLAMA_REPEAT_PENALTY=1.05
INTEL_PLANNER_OLLAMA_NUM_PREDICT=512
INTEL_PLANNER_OLLAMA_JSON_MODE=true
INTEL_PLANNER_SEQ2SEQ_MODEL=intelligence/models/planner_seq2seq
INTEL_PLANNER_SEQ2SEQ_MAX_NEW_TOKENS=384
INTEL_PLANNER_SEQ2SEQ_NUM_BEAMS=4
INTEL_PLANNER_SEQ2SEQ_TEMPERATURE=0.0
INTEL_PLANNER_SEQ2SEQ_MAX_SOURCE_LENGTH=1024
INTEL_CACHE_SIZE=256
```

Notes:
- The local model is loaded once at startup, not per request.
- Scorer mode can be local, ollama, classifier, or hybrid.
- Planner mode can be local, remote, ollama, seq2seq, or hybrid.
- The calibrated scorer (model registry only) uses a classifier for severity/confidence and an LLM for explanation.

## Model registry (easy switching)

The intelligence service can route scoring/planning to different model profiles without code changes.
Profiles are defined in `intelligence/models/registry.json`.
The `foundation-sec` profile uses a calibrated scorer (LLM explanations + classifier-backed confidence) and a strict JSON planner.

Scorer types in the registry:
- `classifier`: deterministic severity/confidence from a lightweight model.
- `ollama`: LLM scorer.
- `calibrated`: classifier-driven severity/confidence with LLM explanations (best accuracy + narrative).

Example profile selection (send in request):
```
{
  "modelProfile": "custom",
  "alert": { ... }
}
```

Or via header:
```
X-Intel-Profile: custom
```

Active default profile:
```
INTEL_ACTIVE_PROFILE=foundation-sec
```

List available profiles:
```
GET /v1/models
```

## C# integration (model profile selection)

These env vars flow from the .NET orchestrator into the Python service:
```
INTEL_MODEL_PROFILE=custom
THREAT_SCORER_MODEL_PROFILE=custom
PLANNER_MODEL_PROFILE=custom
```

If set, the C# HTTP clients pass `modelProfile` in the request body, which the Python service uses
to select the matching registry profile.

## Fine-tuning (LoRA adapters)

Important: GGUF files are inference-only. To fine-tune you need the base model in Hugging Face format
(safetensors or full precision). Train a LoRA adapter, then merge or re-quantize to GGUF if you want
Ollama/llama.cpp deployment.

1) Install training dependencies:
```
pip install -r intelligence/requirements-train.txt
```

2) Prepare JSONL training data (prompt/completion or messages). You can generate it with:
```
NetCore\Tools\TrainingDataGenerator\bin\Debug\net8.0\TrainingDataGenerator.exe --count 50000 --export-hf
```

3) Run the trainer (update --model to your base HF model path or ID):
```
python intelligence/training/fine_tune_lora.py --model <hf_model_or_path> --data training_data.jsonl --output intelligence/adapters/baronllm
```

4) Use the adapter for local inference:
```
INTEL_LOCAL_MODEL=<hf_model_or_path>
INTEL_LOCAL_ADAPTER=intelligence/adapters/baronllm
```

If you want to deploy via Ollama, merge the adapter into the base model, then convert to GGUF using
llama.cpp tooling. Exact steps depend on the base model family and your llama.cpp version.

## 1) Scorer endpoint

POST /v1/score

Request (example):
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

Response:
```
{
  "severity": 55,
  "confidence": 0.65,
  "hypothesis": "Possible scanning activity.",
  "evidence": ["keyword:scan"]
}
```

Batch scoring

POST /v1/score/batch

Request:
```
{
  "alerts": [
    { "type": "PortScanFromIp", "severity": 55, "entities": {"srcIp": "10.0.0.5"} },
    { "type": "BruteForceUser", "severity": 60, "entities": {"username": "bob"} }
  ]
}
```

Response:
```
{
  "results": [
    { "severity": 55, "confidence": 0.65, "hypothesis": "...", "evidence": ["..."] },
    { "severity": 60, "confidence": 0.70, "hypothesis": "...", "evidence": ["..."] }
  ]
}
```

## 2) Planner endpoint

POST /v1/plan

Request (example):
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

Response (example):
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

## Notes

- The current logic is rule-based and deterministic.
- You can replace the heuristic functions with local model inference or remote model calls.

## Custom models (classifier + seq2seq)

These are lightweight baselines to compare against the fine-tuned LLMs.

### Scorer classifier (predictable, deterministic)
Train on the ~3.3k generated examples:
```
python -m intelligence.training.train_scorer_classifier \
  --data intelligence/training/data/real_scorer_train.jsonl \
  --output intelligence/models/scorer_classifier
```

Use it:
```
INTEL_SCORER_MODE=classifier
INTEL_SCORER_CLASSIFIER_PATH=intelligence/models/scorer_classifier
```

### Planner seq2seq (generative, deterministic decoding)
Train on the ~3.3k generated examples:
```
python -m intelligence.training.train_planner_seq2seq \
  --data intelligence/training/data/real_planner_train.jsonl \
  --model google/flan-t5-small \
  --output intelligence/models/planner_seq2seq
```

Use it:
```
INTEL_PLANNER_MODE=seq2seq
INTEL_PLANNER_SEQ2SEQ_MODEL=intelligence/models/planner_seq2seq
```
