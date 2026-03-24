# Thesis Project: SIEM/SOAR Reasoning System

This repository contains:
- The thesis document (`ThesisDraft/`)
- A .NET orchestration engine (`NetCore/Core/`)
- A Python intelligence service for scoring/planning (`intelligence/`)
- Demo/replay scripts and UI helpers (`scripts/`, `demo_ui/`, `case_ui/`)

For full architecture details, see `documentation/SYSTEM_GUIDE.md`.

## 1. Prerequisites

Windows setup used in this project:
- Python 3.11+
- .NET SDK 9.0
- (Optional, for thesis PDF) LaTeX toolchain with `latexmk` (MiKTeX/TeX Live)

## 2. First-Time Setup

From repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install fastapi uvicorn python-dotenv requests scikit-learn joblib torch transformers peft sentencepiece
dotnet restore NetCore/Core/Core.csproj
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## 3. Quick Start (Local Demo, No External Services)

This runs one simulated cycle end-to-end.  
The .NET app auto-starts the Python intelligence service (`python -m intelligence`).

```powershell
.\.venv\Scripts\Activate.ps1
$env:ORCHESTRATOR_MAX_CYCLES = "1"
$env:ORCHESTRATOR_POLL_SECONDS = "0"
dotnet run --project NetCore/Core/Core.csproj
```

Expected behavior:
- Intelligence service starts on `http://127.0.0.1:8080`
- Simulated alert(s) are processed
- Policy/execution/audit output is printed in console
- Run exits after one cycle

## 4. Optional: Webhook Mode + Alert Replay

Terminal 1:

```powershell
.\.venv\Scripts\Activate.ps1
$env:ORCHESTRATOR_WEBHOOK_URL = "http://localhost:5050/"
dotnet run --project NetCore/Core/Core.csproj
```

Terminal 2:

```powershell
.\.venv\Scripts\Activate.ps1
python scripts/replay_alerts.py --siem all --limit 10
```

## 5. Build the Thesis PDF

```powershell
cd ThesisDraft
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
```

Output: `ThesisDraft/main.pdf`

## 6. Useful Paths

- Thesis source: `ThesisDraft/main.tex`
- Core orchestrator entry point: `NetCore/Core/Program.cs`
- Intelligence service entry point: `intelligence/app.py`
- Policy config: `policy_config.json`
- System guide: `documentation/SYSTEM_GUIDE.md`
