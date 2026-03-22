$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Mohamad\PycharmProjects\Thesis"
New-Item -ItemType Directory -Force -Path "logs" | Out-Null

$py = ".\.venv\Scripts\python.exe"
$env:PYTHONUNBUFFERED = "1"

Write-Host "[1/2] Retraining seq2seq planner (flan-t5-base)..."
& $py -u -m intelligence.training.train_planner_seq2seq `
  --data intelligence/training/data/planner_seq2seq_train_canonical.jsonl `
  --model google/flan-t5-base `
  --epochs 3 `
  --batch-size 2 `
  --gradient-accumulation-steps 8 `
  --max-source-length 512 `
  --max-target-length 256 `
  --logging-steps 1 `
  | Tee-Object -FilePath logs/seq2seq_train.log

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[2/2] Evaluating seq2seq planner..."
& $py -m intelligence.training.eval_seq2seq_planner `
  --data intelligence/training/data/planner_seq2seq_train_canonical.jsonl `
  --model-path intelligence/models/planner_seq2seq `
  --test-size 0.1 `
  --output intelligence/training/data/seq2seq_eval.json
