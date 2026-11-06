param([switch]$RealLLM)
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
Push-Location $ProjectRoot
try {
    $PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if ($RealLLM) { & $PythonExe -m soc_assistant.cli ready --require-llm }
    else { & $PythonExe -m soc_assistant.cli ready }
    if ($LASTEXITCODE -ne 0) { throw "Readiness check failed" }
    & $PythonExe -m pytest -q -m "not integration"
    if ($LASTEXITCODE -ne 0) { throw "Fast tests failed" }
    & $PythonExe -m soc_assistant.cli demo --mode C
    if ($LASTEXITCODE -ne 0) { throw "Offline demo failed" }
    if ($RealLLM) {
        $env:SOC_REAL_LLM = "1"
        & $PythonExe -m pytest -q -m integration
        if ($LASTEXITCODE -ne 0) { throw "Real model integration failed" }
    }
} finally {
    Remove-Item Env:SOC_REAL_LLM -ErrorAction SilentlyContinue
    Pop-Location
}
