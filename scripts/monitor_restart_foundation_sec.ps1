$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Mohamad\PycharmProjects\Thesis"
$log = "logs\foundation_sec_train.log"
$maxWaitMinutes = 20
Start-Sleep -Seconds ($maxWaitMinutes * 60)

# If training isn't running, exit
$procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*intelligence.training.train_soar*" }
if (-not $procs) { exit 0 }

if (-not (Test-Path $log)) { exit 0 }

$lines = Get-Content $log -Tail 200
$step = 0
foreach ($line in $lines) {
    if ($line -match "(\d+)/(\d+)") {
        $s = [int]$Matches[1]
        if ($s -gt $step) { $step = $s }
    }
    if ($line -match "loss" -and $line -match "epoch") {
        $step = [Math]::Max($step, 1)
    }
}
$lastWrite = (Get-Item $log).LastWriteTime
$stale = ((Get-Date) - $lastWrite) -gt [TimeSpan]::FromMinutes(10)

if ($step -le 0 -and $stale) {
    foreach ($proc in $procs) {
        Stop-Process -Id $proc.ProcessId -Force
    }

    Start-Process powershell -WorkingDirectory "C:\Users\Mohamad\PycharmProjects\Thesis" `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File scripts\run_training_chain_768.ps1"
}
