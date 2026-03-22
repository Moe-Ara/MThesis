$ErrorActionPreference = "Stop"

$modelName = "baronllm-q6k"
$modelfile = Join-Path $PSScriptRoot "Modelfile.baronllm"

Write-Host "Creating Ollama model $modelName from $modelfile ..."
ollama create $modelName -f $modelfile
Write-Host "Done."
