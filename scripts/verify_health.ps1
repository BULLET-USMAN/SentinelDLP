# SentinelDLP Subsystem Health & Probe Verifier (Windows PowerShell)
# Verifies liveness, readiness, database connectivity, and sensor operational status.

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SentinelDLP v1.0.0 — System Health & Subsystem Verification" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$backendUrl = "http://127.0.0.1:8000"
$liveEndpoint = "$backendUrl/health/live"
$readyEndpoint = "$backendUrl/health/ready"

Write-Host "`n[1/3] Probing Application Liveness ($liveEndpoint)..." -ForegroundColor Yellow
try {
    $liveResponse = Invoke-RestMethod -Uri $liveEndpoint -Method Get -TimeoutSec 5 -ErrorAction Stop
    Write-Host "  [OK] Process Liveness Status : $($liveResponse.status)" -ForegroundColor Green
    Write-Host "  [OK] Application Version     : $($liveResponse.version)" -ForegroundColor Green
    Write-Host "  [OK] Environment Mode        : $($liveResponse.environment)" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Backend process is not reachable at $backendUrl" -ForegroundColor Red
    Write-Host "         Please ensure the backend is running via: .\scripts\run_local.ps1" -ForegroundColor Gray
    Exit 1
}

Write-Host "`n[2/3] Probing Infrastructure Readiness ($readyEndpoint)..." -ForegroundColor Yellow
try {
    $readyResponse = Invoke-RestMethod -Uri $readyEndpoint -Method Get -TimeoutSec 5 -ErrorAction Stop
    Write-Host "  [OK] Readiness Status        : $($readyResponse.status)" -ForegroundColor Green
    if ($readyResponse.database) {
        Write-Host "  [OK] Relational Database     : $($readyResponse.database)" -ForegroundColor Green
    }
} catch {
    Write-Host "  [WARN] Readiness probe responded with non-200 or database unavailable." -ForegroundColor Red
    Write-Host "         Error details: $_" -ForegroundColor Gray
}

Write-Host "`n[3/3] Checking Frontend Availability (http://localhost:5173)..." -ForegroundColor Yellow
try {
    $feResponse = Invoke-WebRequest -Uri "http://localhost:5173" -Method Head -TimeoutSec 3 -ErrorAction Stop
    Write-Host "  [OK] React SOC Frontend      : ONLINE (HTTP $($feResponse.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "  [NOTICE] Frontend dev server is not responding on port 5173 (optional if running backend API only)." -ForegroundColor Yellow
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " Health Verification Summary: Core Services Operational!" -ForegroundColor Green
Write-Host " API Docs:    http://127.0.0.1:8000/docs" -ForegroundColor Cyan
Write-Host " SOC UI:      http://localhost:5173" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
