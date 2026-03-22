$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Mohamad\PycharmProjects\Thesis"
$log = "logs\foundation_sec_train_768.log"
$maxWaitMinutes = 20
Start-Sleep -Seconds ($maxWaitMinutes * 60)

$procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*intelligence.training.train_soar*" }
if (-not $procs) { exit 0 }

$progress = 0
$stale = $true
if (Test-Path $log) {
    $lines = Get-Content $log -Tail 200
    foreach ($line in $lines) {
        if ($line -match "(\d+)/(\d+)") {
            $s = [int]$Matches[1]
            if ($s -gt $progress) { $progress = $s }
        }
        if ($line -match "loss" -and $line -match "epoch") {
            $progress = [Math]::Max($progress, 1)
        }
    }
    $lastWrite = (Get-Item $log).LastWriteTime
    $stale = ((Get-Date) - $lastWrite) -gt [TimeSpan]::FromMinutes(10)
}

if ($progress -le 0 -and $stale) {
    foreach ($proc in $procs) {
        Stop-Process -Id $proc.ProcessId -Force
    }
    Start-Process powershell -WorkingDirectory "C:\Users\Mohamad\PycharmProjects\Thesis" `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File scripts\run_training_chain_768.ps1"
}
