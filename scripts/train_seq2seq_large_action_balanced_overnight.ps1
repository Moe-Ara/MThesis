$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Mohamad\PycharmProjects\Thesis"
New-Item -ItemType Directory -Force -Path "logs" | Out-Null

$py = ".\.venv\Scripts\python.exe"
$env:PYTHONUNBUFFERED = "1"
$env:PYTORCH_ALLOC_CONF = "expandable_segments:True"

Write-Host "[1/3] Build canonical seq2seq dataset with action balancing..."
& $py -m intelligence.training.build_planner_seq2seq_dataset `
  --input intelligence/training/data/real_planner_train.jsonl `
  --output intelligence/training/data/planner_seq2seq_train_canonical_actions.jsonl `
  --rebalance `
  --rebalance-actions `
  --target-per-action 400 `
  --prompt-style minimal

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[2/3] Train seq2seq planner (flan-t5-large, overnight)..."
& $py -u -m intelligence.training.train_planner_seq2seq `
  --data intelligence/training/data/planner_seq2seq_train_canonical_actions.jsonl `
  --model google/flan-t5-large `
  --output intelligence/models/planner_seq2seq_large `
  --epochs 2 `
  --batch-size 1 `
  --gradient-accumulation-steps 8 `
  --max-source-length 384 `
  --max-target-length 192 `
  --learning-rate 5e-5 `
  --gradient-checkpointing `
  --logging-steps 5 `
  --no-fp16 `
  | Tee-Object -FilePath logs/seq2seq_train_large_overnight.log

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[3/3] Eval seq2seq planner (quick 30 samples)..."
& $py -m intelligence.training.eval_seq2seq_planner `
  --data intelligence/training/data/planner_seq2seq_train_canonical_actions.jsonl `
  --model-path intelligence/models/planner_seq2seq_large `
  --test-size 0.1 `
  --limit 30 `
  --output intelligence/training/data/seq2seq_eval_large.json
