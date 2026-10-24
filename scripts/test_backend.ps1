# SentinelDLP Backend Test Runner Script (Windows PowerShell)
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "SentinelDLP - Executing Automated Test Suite" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Split-Path -Parent $scriptDir
Set-Location $rootDir

$pythonExe = Join-Path $rootDir ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    Write-Host "[ERROR] Virtual environment not found at $pythonExe" -ForegroundColor Red
    Write-Host "Please initialize venv: python -m venv .venv; .\.venv\Scripts\pip install -r backend\requirements.txt" -ForegroundColor Yellow
    Exit 1
}

Write-Host "[INFO] Running pytest across backend/tests..." -ForegroundColor Green
& $pythonExe -m pytest -v backend/tests --tb=short
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host "[SUCCESS] All SentinelDLP test suites passed!" -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
} else {
    Write-Host "==================================================" -ForegroundColor Red
    Write-Host "[FAILURE] Tests failed with exit code $exitCode" -ForegroundColor Red
    Write-Host "==================================================" -ForegroundColor Red
}
Exit $exitCode
