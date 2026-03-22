$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Mohamad\PycharmProjects\Thesis"
New-Item -ItemType Directory -Force -Path "logs" | Out-Null

$py = ".\.venv\Scripts\python.exe"
$env:PYTHONUNBUFFERED = "1"

Write-Host "[1/3] Build canonical seq2seq dataset with action balancing..."
& $py -m intelligence.training.build_planner_seq2seq_dataset `
  --input intelligence/training/data/real_planner_train.jsonl `
  --output intelligence/training/data/planner_seq2seq_train_canonical_actions.jsonl `
  --rebalance `
  --rebalance-actions `
  --target-per-action 400 `
  --prompt-style minimal

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[2/3] Train seq2seq planner (flan-t5-base, action-balanced)..."
& $py -u -m intelligence.training.train_planner_seq2seq `
  --data intelligence/training/data/planner_seq2seq_train_canonical_actions.jsonl `
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
  | Tee-Object -FilePath logs/seq2seq_train_base_action_balanced.log

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[3/3] Eval seq2seq planner (quick 30 samples)..."
& $py -m intelligence.training.eval_seq2seq_planner `
  --data intelligence/training/data/planner_seq2seq_train_canonical_actions.jsonl `
  --model-path intelligence/models/planner_seq2seq `
  --test-size 0.1 `
  --limit 30 `
  --output intelligence/training/data/seq2seq_eval.json
