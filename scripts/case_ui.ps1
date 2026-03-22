$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Mohamad\PycharmProjects\Thesis"

# Use venv Python for the UI server.
$env:PATH = "$PWD\.venv\Scripts;" + $env:PATH

# Ensure we read from the same SQLite DB as the engine.
$env:CASE_DB_PATH = "data/cases.db"

# UI server
$env:CASE_UI_HOST = "127.0.0.1"
$env:CASE_UI_PORT = "8100"

python -m case_ui
