# SentinelDLP — UI Screenshot Capture Guide & Asset Checklist

This checklist provides guidelines for capturing high-resolution, professional screenshots of SentinelDLP's 10 operations consoles for portfolio websites, GitHub READMEs, and technical blog posts.

---

## 1. Capture Environment Guidelines

- **Browser Resolution:** 1920 &times; 1080 (Full HD) at 100% zoom.
- **Theme:** Dark theme (native `#0a0e17` slate background).
- **Recommended Tools:** Windows Snipping Tool (`Win + Shift + S`) or ShareX.
- **File Format:** High-quality PNG with minimal compression.
- **Recommended Destination Directory:** `docs/images/screenshots/`

---

## 2. Pre-Capture Preparation (Populating Mock Data)

To ensure the dashboards display rich, realistic operational metrics:
1. Start the platform: `.\scripts\run_local.ps1`
2. Run the interactive demonstration script to populate baseline scans and findings:
   ```powershell
   .\scripts\run_demo.ps1 -NonInteractive
   ```
3. Ingest sample network logs:
   - In the Network Console, load sample Zeek and Suricata EVE logs.
4. Execute validation scenario `SCEN-07` in the Security Lab to generate a multi-stage exfiltration correlation chain.

---

## 3. 10 Core Console Screenshot Checklist

### 1. Executive SOC Dashboard (`/`)
- **File Name:** `01_soc_dashboard_overview.png`
- **Focus Elements:** Top KPI summary cards (Active Alerts, Exfiltration Cases, Sensitive Files Protected), 24-hour Risk Score Distribution chart, and real-time security activity stream.
- **Visual Note:** Ensure the priority triage queue shows at least 2 active items.

### 2. File Scanner Console (`/scanner`)
- **File Name:** `02_file_scanner_inventory.png`
- **Focus Elements:** Authorized scan roots table, active scan progress indicators, and file inventory table with streaming SHA-256 hashes and file category pills.

### 3. Sensitive Data Inventory Console (`/sensitive-data`)
- **File Name:** `03_sensitive_data_classification.png`
- **Focus Elements:** Classification tier summary cards (`CONFIDENTIAL`, `RESTRICTED`), findings table showing masked snippets (e.g. `4532-••••-••••-1111`), and rule tags (PCI Cards, AWS Keys).

### 4. Real-Time File Activity Console (`/monitoring`)
- **File Name:** `04_realtime_file_monitoring.png`
- **Focus Elements:** Live observer status pill (ACTIVE), telemetry event counters, and the live activity stream populated by Server-Sent Events (SSE).

### 5. Threat Risk Intelligence Console (`/threat-risk`)
- **File Name:** `05_threat_risk_scoring.png`
- **Focus Elements:** 0–100 threat score distribution chart, active threat assessments, and the 8 detection rules catalog with primary/secondary weight breakdown.

### 6. Security Alerts Console & Triage Drawer (`/alerts`)
- **File Name:** `06_security_alerts_triage.png`
- **Focus Elements:** Filterable alerts table, severity badges (`CRITICAL`, `HIGH`), and the opened slide-out investigation drawer showing threat score explanation and triage status buttons.

### 7. Exfiltration Detection Workspace (`/exfiltration`)
- **File Name:** `07_exfiltration_correlation_workspace.png`
- **Focus Elements:** Correlation timeline linking sensitive file edits, archive staging (`.zip`), and simulated outbound transfer evidence with circumstantial relationship tags.

### 8. Network Traffic Intelligence & Sensor Status (`/network-intel`)
- **File Name:** `08_network_telemetry_intelligence.png`
- **Focus Elements:** Ingested flow metrics, Suricata SID alert mappings, DNS entropy analysis, and sensor health cards detailing visibility boundaries.

### 9. AI SOC Analyst Workspace (`/ai-analyst`)
- **File Name:** `09_ai_soc_analyst_investigation.png`
- **Focus Elements:** Analyst chat conversation, bounded tool execution timeline (e.g. `get_alert`, `get_investigation_timeline`), grounded MITRE ATT&CK codes, and Confidence Level rating.

### 10. Cyberattack Simulation & Testing Lab (`/security-lab`)
- **File Name:** `10_security_testing_laboratory.png`
- **Focus Elements:** Scenario selector (11 scenarios), Confusion Matrix summary card (100% Precision & Recall), execution timeline, and generated markdown audit report preview.

---

## 4. Portfolio Showcase Image Composition Tips

- **Header / Hero Image:** Create a composite graphic combining the SOC Dashboard (`01`), the AI Analyst (`09`), and the Simulation Lab (`10`) with a subtle dark border for the GitHub README banner.
- **GIF Animations:** Use tools like ScreenToGif or Lottie to capture the real-time SSE event feed updating dynamically when a file is edited.
