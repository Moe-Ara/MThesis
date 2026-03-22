param(
    [Parameter(Mandatory = $true)]
    [int]$Pid,
    [string]$ModelPath = "intelligence/models/planner_nn_reasoning_20260306",
    [string]$Data = "intelligence/training/data/planner_seq2seq_train_compact_reasoning.jsonl",
    [string]$Output = "intelligence/training/data/nn_eval_reasoning_20260306.json",
    [int]$CheckSeconds = 30,
    [string]$LogPath = "logs/monitor_planner_nn_reasoning.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$logDir = Split-Path -Parent $LogPath
if ($logDir) {
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
}

function Write-Log {
    param([string]$Message)
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$ts $Message" | Tee-Object -FilePath $LogPath -Append
}

$python = Join-Path $PSScriptRoot "..\\.venv\\Scripts\\python.exe"
if (-not (Test-Path $python)) {
    $python = "python"
}

Write-Log "Monitoring training PID $Pid..."
while ($true) {
    $proc = Get-Process -Id $Pid -ErrorAction SilentlyContinue
    if (-not $proc) {
        break
    }
    $cpu = if ($proc.CPU -ne $null) { [math]::Round($proc.CPU, 2) } else { 0 }
    Write-Log "Still running. CPU=$cpu"
    Start-Sleep -Seconds $CheckSeconds
}

Write-Log "Process ended. Running eval..."
& $python -m intelligence.training.eval_planner_nn --data $Data --model-path $ModelPath --output $Output | Tee-Object -FilePath $LogPath -Append
Write-Log "Eval finished. Output=$Output"
