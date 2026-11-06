param([switch]$DemoOnly, [switch]$FullAttack, [string]$PythonVersion = "3.12")
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
Push-Location $ProjectRoot
try {
    & py "-$PythonVersion" -c "import struct; assert struct.calcsize('P') == 8, '64-bit Python required'"
    if ($LASTEXITCODE -ne 0) { throw "Install Python 3.12 x64 from python.org, including the py launcher." }
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        & py "-$PythonVersion" -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw "venv failed" }
    }
    $PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    & $PythonExe -m pip install -r requirements-lock.txt
    if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed" }
    & $PythonExe -m pip install --no-build-isolation --no-deps -e .
    if ($LASTEXITCODE -ne 0) { throw "Application installation failed" }
    if (-not $DemoOnly) {
        & $PythonExe -m pip install -r requirements-llm.txt --only-binary=llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
        if ($LASTEXITCODE -ne 0) { throw "CPU wheel unavailable. See docs/WINDOWS.md for the documented C++ build option." }
        & $PythonExe -m soc_assistant.cli prepare --model
        if ($LASTEXITCODE -ne 0) { throw "Model preparation failed" }
    }
    if ($FullAttack) {
        & $PythonExe -m soc_assistant.cli prepare --attack
        if ($LASTEXITCODE -ne 0) { throw "ATT&CK download failed" }
        $ConfigText = Get-Content config.toml -Raw -Encoding UTF8
        $ConfigText = $ConfigText.Replace('snapshot = "knowledge/enterprise-demo.json"', 'snapshot = "knowledge/enterprise-full.json"')
        [System.IO.File]::WriteAllText((Join-Path $ProjectRoot "config.toml"), $ConfigText, [System.Text.UTF8Encoding]::new($false))
    }
    & $PythonExe -m soc_assistant.cli prepare --index
    if ($LASTEXITCODE -ne 0) { throw "Index preparation failed" }
    & $PythonExe -m soc_assistant.cli schemas
    if ($LASTEXITCODE -ne 0) { throw "Schema export failed" }
    if ($DemoOnly) { & $PythonExe -m soc_assistant.cli ready }
    else { & $PythonExe -m soc_assistant.cli ready --require-llm }
    if ($LASTEXITCODE -ne 0) { throw "Readiness checks failed" }
    Write-Host "Ready. Run .\scripts\Start.ps1. Downloads are used only by Setup/prepare."
} finally { Pop-Location }
