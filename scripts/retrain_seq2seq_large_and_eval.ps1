$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Mohamad\PycharmProjects\Thesis"
New-Item -ItemType Directory -Force -Path "logs" | Out-Null

$py = ".\.venv\Scripts\python.exe"
$env:PYTHONUNBUFFERED = "1"

Write-Host "[1/3] Build canonical seq2seq dataset (minimal prompt)..."
& $py -m intelligence.training.build_planner_seq2seq_dataset `
  --input intelligence/training/data/real_planner_train.jsonl `
  --output intelligence/training/data/planner_seq2seq_train_canonical.jsonl `
  --rebalance `
  --prompt-style minimal

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[2/3] Retraining seq2seq planner (flan-t5-large)..."
& $py -u -m intelligence.training.train_planner_seq2seq `
  --data intelligence/training/data/planner_seq2seq_train_canonical.jsonl `
  --model google/flan-t5-large `
  --output intelligence/models/planner_seq2seq_large `
  --epochs 3 `
  --batch-size 1 `
  --gradient-accumulation-steps 16 `
  --max-source-length 768 `
  --max-target-length 256 `
  --logging-steps 1 `
  | Tee-Object -FilePath logs/seq2seq_train_large.log

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[3/3] Evaluating seq2seq planner..."
& $py -m intelligence.training.eval_seq2seq_planner `
  --data intelligence/training/data/planner_seq2seq_train_canonical.jsonl `
  --model-path intelligence/models/planner_seq2seq_large `
  --test-size 0.1 `
  --output intelligence/training/data/seq2seq_eval.json
