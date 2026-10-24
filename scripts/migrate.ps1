# SentinelDLP Database Migration Utility (Windows PowerShell)
param (
    [string]$Action = "upgrade",
    [string]$Revision = "head"
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Split-Path -Parent $scriptDir
Set-Location (Join-Path $rootDir "backend")

$alembicExe = Join-Path $rootDir ".venv\Scripts\alembic.exe"
if (-not (Test-Path $alembicExe)) {
    Write-Host "[ERROR] Alembic executable not found at $alembicExe" -ForegroundColor Red
    Exit 1
}

Write-Host "[INFO] Running Alembic $Action $Revision..." -ForegroundColor Green
& $alembicExe $Action $Revision
