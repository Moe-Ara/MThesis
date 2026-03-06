# Dataset Downloads + LLM Dataset Pipeline

This guide provides scripted downloads for public security datasets and a pipeline that uses a local LLM to generate training data.

## Download scripts

All scripts write to `data/external/` by default.

### CIC-IDS2018

```
powershell -ExecutionPolicy Bypass -File scripts/datasets/download_cic_ids2018.ps1
```

### MITRE ATT&CK STIX

```
powershell -ExecutionPolicy Bypass -File scripts/datasets/download_attack_stix.ps1
```

### Mordor / Security-Datasets

```
powershell -ExecutionPolicy Bypass -File scripts/datasets/download_mordor.ps1
```

### DARPA Transparent Computing

```
powershell -ExecutionPolicy Bypass -File scripts/datasets/download_darpa_tc.ps1
```

If you want the repo only (no dataset download), add `-SkipData`.

## LLM-assisted dataset generation

The pipeline reads samples from the downloaded datasets and uses a local LLM (Ollama) to produce scorer and planner training samples. Outputs are normalized to the DecisionPlan schema expected by the planner.

1) Ensure Ollama is running and the model is created (`baronllm-q6k` by default).
2) Run the pipeline:

```
python intelligence/training/llm_dataset_pipeline.py --output training_data.jsonl --max-records 80 --mode both
```

The output JSONL uses chat-style `messages` and can be fed into the fine-tuning script. Dataset-specific parsers are included for CIC-IDS2018, Mordor, and DARPA Transparent Computing.

## Notes

- CIC-IDS2018 is hosted on AWS Open Data and is very large.
- Mordor (Security-Datasets) is a GitHub repo with multiple datasets.
- DARPA Transparent Computing data is hosted in a Google Drive folder.
- MITRE ATT&CK STIX bundles are pulled from the official attack-stix-data repo.
