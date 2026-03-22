$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Mohamad\PycharmProjects\Thesis"
New-Item -ItemType Directory -Force -Path "logs" | Out-Null

Write-Host "[1/2] Training foundation-sec planner (max-length 1024)..."
$env:PYTHONUNBUFFERED = "1"
python -u -m intelligence.training.train_soar `
  --task planner `
  --data intelligence/training/data/planner_seq2seq_train_balanced.jsonl `
  --output models/foundation-sec-planner-lora `
  --max-length 1024 `
  --epochs 2 `
  --batch-size 1 `
  --gradient-accumulation-steps 16 `
  | Tee-Object -FilePath logs/foundation_sec_train.log

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[2/2] Retraining seq2seq planner (flan-t5-base)..."
python -u -m intelligence.training.train_planner_seq2seq `
  --data intelligence/training/data/planner_seq2seq_train_balanced.jsonl `
  --epochs 3 `
  --batch-size 2 `
  --gradient-accumulation-steps 8 `
  --max-source-length 512 `
  --max-target-length 256 `
  --logging-steps 1 `
  | Tee-Object -FilePath logs/seq2seq_train.log
