$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Mohamad\PycharmProjects\Thesis"
$py = ".\\.venv\\Scripts\\python.exe"
Write-Host "Waiting for export_to_ollama to finish..."
while (Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*intelligence.training.export_to_ollama*" }) {
    Start-Sleep -Seconds 30
}
Write-Host "Export finished. Running comparison..."
& $py -m intelligence.training.compare_models `
  --skip-scorer `
  --planner-data intelligence/training/data/planner_seq2seq_train_balanced.jsonl `
  --limit 30 `
  --output intelligence/training/data/model_compare_planner.json
