# SentinelDLP — Technical Video Walkthrough Script (5–8 Minutes)

**Target Video Duration:** ~6 to 8 minutes  
**Format:** Screen recording with split screen / PiP webcam and voice narration  
**Goal:** Showcase SentinelDLP's architectural depth, detection accuracy, and enterprise SOC workflows to recruiters, hiring managers, and security peers.

---

## Video Outline & Timestamp Breakdown

| Scene | Duration | Title | Core Focus |
|---|---|---|---|
| **Scene 1** | 0:00 – 1:00 | Introduction & Executive SOC Dashboard | Project purpose, high-density dashboard, KPI metrics |
| **Scene 2** | 1:00 – 2:15 | Secure File Scanning & Zero-Leakage Masking | 64KB SHA-256 chunking, Luhn validation, masked storage |
| **Scene 3** | 2:15 – 3:30 | Real-Time Monitoring & SSE Telemetry | Watchdog observer, 400ms debouncing, live event stream |
| **Scene 4** | 3:30 – 4:45 | Risk Scoring & Exfiltration Correlation | 0–100 threat score, temporal staging + egress correlation |
| **Scene 5** | 4:45 – 6:00 | Cyberattack Simulation & Confusion Matrix Lab | Harmless attack sandbox, 11 scenarios, accuracy metrics |
| **Scene 6** | 6:00 – 7:15 | AI SOC Analyst & Evidence Grounding | Bounded tools, anti-hallucination, local Ollama readiness |
| **Scene 7** | 7:15 – 8:00 | Security Hardening & Automated Testing Suite | 171 automated tests, timing-safe RBAC, wrap-up |

---

## Detailed Scene-by-Scene Script

### Scene 1: Introduction & Executive SOC Dashboard (0:00 – 1:00)
- **Visual:** Open browser to `http://localhost:5173`. Show the dark-themed SOC Overview page. Highlight the KPI tiles, 24-hour risk distribution chart, and live event feed.
- **Narration:**
  > "Hello everyone! Today I’m walking you through **SentinelDLP**, an enterprise-grade Data Loss Prevention and threat detection platform built with FastAPI, React, and PostgreSQL across 12 rigorous engineering phases.
  > 
  > Traditional DLP solutions often suffer from severe alert fatigue and privacy dilemmas when streaming enterprise telemetry to public cloud AI services. SentinelDLP solves this through defense-in-depth principles: zero-leakage privacy redaction, explainable 0–100 threat scoring, and a locally hosted AI SOC Analyst that validates evidence against local ground truth.
  > 
  > As you can see on the unified SOC dashboard, we have real-time visibility into active alerts, protected sensitive files, live filesystem sensors, and detection telemetry streams."

---

### Scene 2: Secure File Scanning & Zero-Leakage Masking (1:00 – 2:15)
- **Visual:** Navigate to the **File Scanner Console** (`/scanner`). Click "Start Scan" on the authorized root directory (`sample_data`). Show files being discovered and SHA-256 hashes generated. Then click into **Sensitive Data** (`/sensitive-data`).
- **Narration:**
  > "Let’s start with data discovery. SentinelDLP features a streaming SHA-256 file scanner that processes files in 64-kilobyte chunks, ensuring low memory consumption even when inspecting large archives.
  > 
  > When we inspect sensitive findings, our classification engine doesn't just rely on naive pattern matching. It uses algorithmic validation like Luhn checksums for credit cards and Shannon entropy analysis for API tokens and private keys.
  > 
  > Most importantly, notice our **zero-leakage redaction**: sensitive credit card numbers and access tokens are irrevocably masked—for instance, showing only the first four and last four digits—before they ever hit the database or the user interface."

---

### Scene 3: Real-Time Filesystem Monitoring & SSE Stream (2:15 – 3:30)
- **Visual:** Navigate to **File Activity Console** (`/monitoring`). Show the live telemetry counters. Open a terminal side-by-side and create/modify a file inside `sample_data/`. Show the event appearing instantly in the live feed without manual page refresh.
- **Narration:**
  > "Next is our real-time filesystem monitoring engine. Powered by Python's `watchdog` library, SentinelDLP continuously monitors authorized storage roots.
  > 
  > In enterprise environments, rapid file operations can cause event storms. SentinelDLP solves this with a **400-millisecond sliding-window debouncing engine** and a thread-safe 5,000-event bounded queue.
  > 
  > File changes, renames, and deletions are streamed straight to the frontend via Server-Sent Events with sub-second latency. Notice also our commitment to telemetry modesty: events strictly record their observer source and never fabricate unverified process or user attribution."

---

### Scene 4: Risk Scoring & Exfiltration Correlation (3:30 – 4:45)
- **Visual:** Navigate to **Risk Intelligence** (`/threat-risk`) and **Security Alerts** (`/alerts`). Open the slide-out drawer for an alert to show the threat score breakdown (Primary Rule vs. Secondary Rule weights). Then visit **Exfiltration Detection** (`/exfiltration`).
- **Narration:**
  > "How do we prioritize these events without generating false alarms? SentinelDLP operates on a core philosophy: **File sensitivity is context, not proof of malice.**
  > 
  > Our threat engine uses a deterministic 0–100 scoring model. An ordinary edit to a confidential document only earns a Low risk score. But if it's coupled with abnormal modification velocity, bulk file renaming, or archive staging, the score escalates dynamically into High or Critical bands.
  > 
  > In our Exfiltration Correlation engine, we link file modifications, archive creation, and outbound network transfers across configurable temporal windows, clearly tagging evidence links as circumstantial or verified."

---

### Scene 5: Cyberattack Simulation & Confusion Matrix Lab (4:45 – 6:00)
- **Visual:** Navigate to **Attack Simulation Lab** (`/security-lab`). Select `SCEN-01` (Benign baseline) and click "Run Scenario", showing negative detection (TN). Then select `SCEN-07` (Potential Data Exfiltration) and click "Run Scenario", showing positive multi-signal detection (TP). Point out the Confusion Matrix and precision/recall stats.
- **Narration:**
  > "To objectively validate our detection rules, Phase 10 introduced an automated Cyberattack Simulation Laboratory.
  > 
  > It features 11 predefined, strictly harmless attack-like scenarios—ranging from ransomware-like bulk renaming to multi-signal exfiltration chains. All test artifacts are strictly isolated inside a dedicated sandbox with automated cleanup.
  > 
  > As the simulation runs, our analytics engine calculates real-time confusion matrix metrics: True Positives, False Positives, Precision, and Recall. Across all synthetic test fixtures, SentinelDLP demonstrates 100% precision and zero false positives on benign controls."

---

### Scene 6: AI SOC Analyst & Evidence Grounding (6:00 – 7:15)
- **Visual:** Navigate to **AI SOC Analyst** (`/ai-analyst`). Select an active alert and ask: *"Analyze this alert and summarize the staging and exfiltration evidence."* Show the tool invocations appearing in the timeline, followed by the structured report with MITRE ATT&CK codes and Confidence Level.
- **Narration:**
  > "Here is one of SentinelDLP's most powerful capabilities: the AI SOC Analyst.
  > 
  > Many security teams are hesitant to use LLMs because of hallucinations and prompt injections. SentinelDLP solves both.
  > 
  > First, the AI agent has access only to 9 bounded, server-side read-only tools, limited to at most 6 calls per run. Second, all untrusted telemetry logs are defensively enclosed in `<untrusted_telemetry>` tags to neutralize prompt injections.
  > 
  > Third, our post-generation verifier cross-references every cited record ID against the relational database. If the model hallucinates an ID, it is stripped immediately. Best of all, it works locally with zero cloud dependencies using Ollama or our deterministic mock provider."

---

### Scene 7: Security Hardening & Conclusion (7:15 – 8:00)
- **Visual:** Switch to terminal. Run `.\.venv\Scripts\python.exe -m pytest -q` showing **171 passed** tests in ~18s. Show the GitHub repository page.
- **Narration:**
  > "Finally, Phase 11 and 12 focused on release readiness and security hardening: timing-safe token comparison, RBAC tiers, 10-megabyte payload size limits, and canonical path traversal defenses.
  > 
  > Our automated test suite includes **171 passing pytest tests** covering every detection rule, API contract, and security guardrail.
  > 
  > SentinelDLP v1.0.0 is open source under the MIT License and completely reproducible locally or via Docker Compose. Check out the link in the description for the full source code and technical documentation. Thank you for watching!"
