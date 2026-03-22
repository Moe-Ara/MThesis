$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Mohamad\PycharmProjects\Thesis"
New-Item -ItemType Directory -Force -Path "logs" | Out-Null

$py = ".\.venv\Scripts\python.exe"
$env:PYTHONUNBUFFERED = "1"

Write-Host "[1/2] Train seq2seq planner (canonical dataset, safe GPU settings)..."
& $py -u -m intelligence.training.train_planner_seq2seq `
  --data intelligence/training/data/planner_seq2seq_train_canonical.jsonl `
  --model google/flan-t5-base `
  --output intelligence/models/planner_seq2seq `
  --epochs 3 `
  --batch-size 4 `
  --gradient-accumulation-steps 4 `
  --max-source-length 512 `
  --max-target-length 256 `
  --learning-rate 1e-4 `
  --gradient-checkpointing `
  --logging-steps 5 `
  --no-fp16 `
  | Tee-Object -FilePath logs/seq2seq_train.log

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[2/2] Eval seq2seq planner..."
& $py -m intelligence.training.eval_seq2seq_planner `
  --data intelligence/training/data/planner_seq2seq_train_canonical.jsonl `
  --model-path intelligence/models/planner_seq2seq `
  --test-size 0.1 `
  --output intelligence/training/data/seq2seq_eval.json
