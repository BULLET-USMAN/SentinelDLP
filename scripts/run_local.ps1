# SentinelDLP Local Development Launcher (Windows PowerShell)
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "SentinelDLP - Local Development Launcher" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Split-Path -Parent $scriptDir
Set-Location $rootDir

$pythonExe = Join-Path $rootDir ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    Write-Host "[ERROR] Virtual environment not found at $pythonExe" -ForegroundColor Red
    Exit 1
}

Write-Host "[INFO] Starting Backend API on http://127.0.0.1:8000 ..." -ForegroundColor Green
Start-Process -FilePath $pythonExe -ArgumentList "-m", "uvicorn", "app.main:app", "--app-dir", "backend", "--port", "8000", "--host", "127.0.0.1", "--reload"

Write-Host "[INFO] Starting Frontend Dev Server on http://localhost:5173 ..." -ForegroundColor Green
Set-Location (Join-Path $rootDir "frontend")
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "npm.cmd", "run", "dev"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "SentinelDLP is launching!" -ForegroundColor Green
Write-Host "Backend API:  http://127.0.0.1:8000/docs" -ForegroundColor Yellow
Write-Host "Frontend App: http://localhost:5173" -ForegroundColor Yellow
Write-Host "Health Probe: http://127.0.0.1:8000/health/live" -ForegroundColor Yellow
Write-Host "==================================================" -ForegroundColor Cyan
