$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Mohamad\PycharmProjects\Thesis"

# Use venv Python for the UI server.
$env:PATH = "$PWD\.venv\Scripts;" + $env:PATH

# Where the demo trace is written.
$env:DEMO_TRACE_PATH = "data/demo_trace.json"
$env:REASONING_DATA_DIR = "data/reasoning"

# UI server
$env:DEMO_UI_HOST = "127.0.0.1"
$env:DEMO_UI_PORT = "8099"

# Start case dashboard in a separate window.
$caseArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "scripts\\case_ui.ps1"
)
Start-Process -FilePath "powershell" -ArgumentList $caseArgs -WorkingDirectory $PWD | Out-Null

python -m demo_ui
