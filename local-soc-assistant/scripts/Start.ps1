param([int]$Port = 8501)
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
Push-Location $ProjectRoot
try {
    $PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $PythonExe)) { throw "Run .\scripts\Setup.ps1 first." }
    & $PythonExe -m soc_assistant.cli ready
    if ($LASTEXITCODE -ne 0) { throw "Snapshot/index not ready; see README." }
    $env:HF_HUB_OFFLINE = "1"
    $env:HF_HUB_DISABLE_TELEMETRY = "1"
    $env:TRANSFORMERS_OFFLINE = "1"
    $env:DO_NOT_TRACK = "1"
    & $PythonExe -m streamlit run app.py --server.address 127.0.0.1 --server.port $Port --browser.gatherUsageStats false
    if ($LASTEXITCODE -ne 0) { throw "Application stopped with an error." }
} finally { Pop-Location }
