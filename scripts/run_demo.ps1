# SentinelDLP Interactive Demonstration & Portfolio Tour (Windows PowerShell)
# Guides an evaluator or technical reviewer through SentinelDLP's core cybersecurity workflows.

param(
    [string]$ApiBase = "http://127.0.0.1:8000",
    [switch]$NonInteractive
)

function Write-Section($num, $title) {
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host " STEP $num : $title" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Wait-Reviewer() {
    if (-not $NonInteractive) {
        Write-Host "`nPress [ENTER] to proceed to the next step..." -ForegroundColor Gray
        Read-Host | Out-Null
    }
}

Write-Host "############################################################" -ForegroundColor Green
Write-Host "#                                                          #" -ForegroundColor Green
Write-Host "#         SentinelDLP v1.0.0 Technical Portfolio Demo      #" -ForegroundColor Green
Write-Host "#                                                          #" -ForegroundColor Green
Write-Host "############################################################" -ForegroundColor Green
Write-Host "Target API: $ApiBase" -ForegroundColor Gray

# Step 1: Health & Liveness
Write-Section 1 "Verifying System Liveness & Subsystem Status"
try {
    $health = Invoke-RestMethod -Uri "$ApiBase/health/live" -Method Get
    Write-Host "[+] Application Status : $($health.status)" -ForegroundColor Green
    Write-Host "[+] Release Version    : $($health.version)" -ForegroundColor Green
    Write-Host "[+] Environment        : $($health.environment)" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to connect to backend at $ApiBase. Please start it using '.\scripts\run_local.ps1'" -ForegroundColor Red
    Exit 1
}
Wait-Reviewer

# Step 2: List Authorized Scan Roots
Write-Section 2 "Querying Authorized Scan Roots (Defensive Confinement)"
try {
    $roots = Invoke-RestMethod -Uri "$ApiBase/api/v1/scanner/roots" -Method Get
    Write-Host "[+] Found $($roots.Count) pre-authorized filesystem root(s):" -ForegroundColor Green
    foreach ($r in $roots) {
        Write-Host "    - Path: $($r.path) (Label: $($r.label), Active: $($r.is_active))" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[-] Failed to fetch scan roots: $_" -ForegroundColor Red
}
Wait-Reviewer

# Step 3: Trigger Background Inventory & SHA-256 Hashing Scan
Write-Section 3 "Executing File Scan & Streaming SHA-256 Inventory"
try {
    Write-Host "[*] Submitting background scan job on authorized root 'sample_data'..." -ForegroundColor Yellow
    $body = @{ path = "sample_data" } | ConvertTo-Json
    $scan = Invoke-RestMethod -Uri "$ApiBase/api/v1/scans" -Method Post -Body $body -ContentType "application/json"
    Write-Host "[+] Scan initiated! Scan ID: $($scan.id)" -ForegroundColor Green
    Write-Host "    Current Status: $($scan.status)" -ForegroundColor Green
    Write-Host "    Streaming 64KB-chunked SHA-256 hashing and mime detection active." -ForegroundColor Gray
} catch {
    Write-Host "[*] Scan initiation response: $_" -ForegroundColor Yellow
}
Wait-Reviewer

# Step 4: Sensitive Data Classification & Zero-Leakage Masking
Write-Section 4 "Inspecting Classified Sensitive Assets (Zero-Leakage Masking)"
try {
    $findings = Invoke-RestMethod -Uri "$ApiBase/api/v1/classification/findings?limit=5" -Method Get
    Write-Host "[+] Sample Sensitive Findings (Masked at Rest):" -ForegroundColor Green
    if ($findings.items -and $findings.items.Count -gt 0) {
        foreach ($f in $findings.items) {
            Write-Host "    - Category: $($f.category) | Rule: $($f.rule_id) | Snippet: $($f.masked_snippet)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "    [Note] Zero-leakage redaction enforces automatic masking on cards (Luhn-valid) and keys." -ForegroundColor Gray
    }
} catch {
    Write-Host "[*] Query completed: $_" -ForegroundColor Gray
}
Wait-Reviewer

# Step 5: Explainable Threat Risk Engine & Alerts
Write-Section 5 "Reviewing Risk Intelligence & Security Detection Alerts"
try {
    $alerts = Invoke-RestMethod -Uri "$ApiBase/api/v1/alerts?limit=5" -Method Get
    Write-Host "[+] Security Alerts Evaluated by Deterministic 0-100 Threat Scoring:" -ForegroundColor Green
    if ($alerts.items -and $alerts.items.Count -gt 0) {
        foreach ($a in $alerts.items) {
            Write-Host "    - [Score: $($a.threat_score)] [Severity: $($a.severity)] $($a.title)" -ForegroundColor Yellow
            Write-Host "      Rule: $($a.rule_code) | Status: $($a.status)" -ForegroundColor Gray
        }
    } else {
        Write-Host "    [Note] Alerts trigger when threat score >= 30, with sliding-window repeat suppression." -ForegroundColor Gray
    }
} catch {
    Write-Host "[*] Alert review status: $_" -ForegroundColor Gray
}
Wait-Reviewer

# Step 6: Cyberattack Simulation & Validation Lab
Write-Section 6 "Executing Harmless Cyberattack Simulation (SCEN-01 Benign Baseline)"
try {
    Write-Host "[*] Launching validation scenario SCEN-01 in isolated sandbox..." -ForegroundColor Yellow
    $simBody = @{ scenario_id = "SCEN-01" } | ConvertTo-Json
    $simResult = Invoke-RestMethod -Uri "$ApiBase/api/v1/simulation/execute" -Method Post -Body $simBody -ContentType "application/json"
    Write-Host "[+] Simulation Executed Successfully!" -ForegroundColor Green
    Write-Host "    Scenario: $($simResult.scenario_id) ($($simResult.scenario_name))" -ForegroundColor Green
    Write-Host "    Status:   $($simResult.status)" -ForegroundColor Green
    Write-Host "    Execution Time: $($simResult.duration_ms) ms" -ForegroundColor Green
    Write-Host "    Sandbox Confined to: sample_data/simulation_lab/ (Automatic Cleanup)" -ForegroundColor Gray
} catch {
    Write-Host "[*] Simulation status note: $_" -ForegroundColor Gray
}
Wait-Reviewer

# Step 7: SOC Operations Dashboard & AI Analyst
Write-Section 7 "Enterprise Operations Dashboard & AI SOC Analyst"
Write-Host "[+] SentinelDLP Web Interfaces:" -ForegroundColor Green
Write-Host "    - Executive SOC Dashboard : http://localhost:5173" -ForegroundColor Yellow
Write-Host "    - AI SOC Analyst Console  : http://localhost:5173/ai-analyst" -ForegroundColor Yellow
Write-Host "    - Attack Simulation Lab   : http://localhost:5173/security-lab" -ForegroundColor Yellow
Write-Host "    - API Interactive Swagger : http://127.0.0.1:8000/docs" -ForegroundColor Yellow
Write-Host "`n[DEMO COMPLETE] SentinelDLP v1.0.0 is ready for evaluation and local demonstration." -ForegroundColor Green
