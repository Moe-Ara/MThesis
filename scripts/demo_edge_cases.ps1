$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Mohamad\PycharmProjects\Thesis"

# Ensure venv Python is used by the orchestrator when it starts the intelligence service.
$env:PATH = "$PWD\.venv\Scripts;" + $env:PATH

# Use the custom NN profile for a fast demo.
$env:INTEL_MODEL_REGISTRY = "intelligence/models/registry.json"
$env:INTEL_ACTIVE_PROFILE = "custom-nn"
$env:INTEL_MODEL_PROFILE = "custom-nn"
$env:THREAT_SCORER_MODEL_PROFILE = "custom-nn"
$env:PLANNER_MODEL_PROFILE = "custom-nn"

# Ensure local modes are used if registry lookups are not applied (health/status).
$env:INTEL_SCORER_MODE = "classifier"
$env:INTEL_SCORER_CLASSIFIER_PATH = "intelligence/models/scorer_classifier"
$env:INTEL_PLANNER_MODE = "custom_nn"
$env:INTEL_PLANNER_NN_MODEL_PATH = "intelligence/models/planner_nn"

# Bind intelligence service to a dedicated port to avoid conflicts.
$env:INTEL_HOST = "0.0.0.0"
$env:INTEL_PORT = "8094"
$env:THREAT_SCORER_BASEURL = "http://localhost:8094"
$env:PLANNER_API_BASEURL = "http://localhost:8094"

# Emit a demo trace file for the UI.
$env:DEMO_TRACE_PATH = "data/demo_trace.json"
$env:DEMO_TRACE_JSONL_PATH = "data/demo_trace.jsonl"
$env:DEMO_TRACE_ONLY_SUCCESS = "false"
$env:DEMO_TRACE_MAX_AUDIT = "50"
$env:REASONING_DATA_DIR = "data/reasoning"
$env:CASE_DB_PATH = "data/cases.db"
$env:NORMALIZATION_ALLOW_EMPTY_ENTITIES = "true"

# Include edge cases to stress normalization and planning.
$env:SIMULATOR_ALERT_COUNT = "4"
$env:SIMULATOR_INCLUDE_EDGE_CASES = "true"

# Keep the demo fully local (no external executor calls).
$env:TICKETING_API_BASEURL = ""
$env:NOTIFICATION_API_BASEURL = ""
$env:FIREWALL_API_BASEURL = ""

# Single-cycle demo run.
$env:ORCHESTRATOR_MAX_CYCLES = "1"
$env:ORCHESTRATOR_POLL_SECONDS = "0"
$env:ORCHESTRATOR_DRY_RUN = "false"

# Start the intelligence service explicitly and wait for health.
$py = "C:\Users\Mohamad\PycharmProjects\Thesis\.venv\Scripts\python.exe"
$logDir = "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$stdout = Join-Path $logDir "intel_edge.log"
$stderr = Join-Path $logDir "intel_edge.err.log"
if (Test-Path $stdout) { Remove-Item $stdout -Force }
if (Test-Path $stderr) { Remove-Item $stderr -Force }

# Stop any existing process listening on the demo port to ensure updated code loads.
try {
    $existing = Get-NetTCPConnection -LocalPort 8094 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existing -and $existing.OwningProcess) {
        Stop-Process -Id $existing.OwningProcess -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
} catch {
    # ignore if not supported
}

$intelProc = Start-Process -FilePath $py -ArgumentList "-u", "-m", "intelligence" `
    -WorkingDirectory "C:\Users\Mohamad\PycharmProjects\Thesis" `
    -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr

$deadline = (Get-Date).AddSeconds(120)
$healthy = $false
while ((Get-Date) -lt $deadline) {
    try {
        $resp = Invoke-RestMethod -Uri http://127.0.0.1:8094/health -TimeoutSec 5
        if ($resp.ok -eq $true) { $healthy = $true; break }
    } catch {
        Start-Sleep -Seconds 2
    }
}

if (-not $healthy) {
    Write-Host "Intelligence service failed to become healthy within 120s."
    if (Test-Path $stdout) { Get-Content $stdout -Tail 50 }
    if (Test-Path $stderr) { Get-Content $stderr -Tail 50 }
    if ($intelProc -and -not $intelProc.HasExited) { Stop-Process -Id $intelProc.Id -Force }
    throw "Intelligence startup failed"
}

# Run the engine (build if needed).
$exe = "NetCore/Core/bin/Debug/net9.0/Core.dll"
if (-not (Test-Path $exe)) {
    dotnet build NetCore/Core/Core.csproj
}
dotnet exec $exe

# Stop intelligence service after demo run.
if ($intelProc -and -not $intelProc.HasExited) {
    Stop-Process -Id $intelProc.Id -Force
}
