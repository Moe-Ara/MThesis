$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$sourceDir = Join-Path $root "mermaid"
$configPath = Join-Path $sourceDir "mermaid.config.json"
$outputDir = "ThesisDraft/Figures/Diagrams"

$diagrams = @(
  "Architecture_Overview",
  "Class_Orchestrator",
  "Class_Domain_Model",
  "Sequence_Execution_and_Rollback",
  "Dataset_Pipeline",
  "Requirements_Traceability",
  "Evaluation_Workflow",
  "SIEM_Traditional_SOAR",
  "SIEM_Thesis_Plugin_Structure",
  "Contribution_Delta_Map",
  "Implementation_Runtime_Boundary",
  "Implementation_Extensibility_Points"
)

foreach ($name in $diagrams) {
  $input = Join-Path $sourceDir "$name.mmd"
  $output = Join-Path $outputDir "$name.png"
  $npxArgs = @(
    "--yes",
    "--package", "@mermaid-js/mermaid-cli",
    "mmdc",
    "-c", $configPath,
    "-i", $input,
    "-o", $output
  )
  & npx @npxArgs
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to render $name"
  }
}

Write-Host "Rendered $($diagrams.Count) Mermaid diagrams to $outputDir"
