# LinkedIn Project Showcase Post Draft

Below is a ready-to-publish LinkedIn post announcing the release and technical highlights of **SentinelDLP v1.0.0**.

---

### **Headline / Hook**
🚀 Excited to unveil **SentinelDLP (v1.0.0)** — an open-source, AI-powered Data Loss Prevention & Exfiltration Detection Platform engineered from the ground up for modern cybersecurity operations!

---

### **Post Body**

Over the past several weeks, I set out to build a defensive cybersecurity platform that bridges low-level endpoint telemetry with explainable threat intelligence and local AI assistance.

Most DLP solutions suffer from three persistent headaches:
1️⃣ Alert fatigue caused by treating sensitive data presence as an active attack.
2️⃣ Privacy risks when sending sensitive logs or intellectual property to cloud AI models.
3️⃣ Siloed telemetry that fails to correlate filesystem changes with archive staging and network egress.

**SentinelDLP solves these challenges through defense-in-depth engineering across 12 modular phases:**

🛡️ **Streaming SHA-256 Hashing & Deep Content Inspection**:
Memory-bounded scanning (64 KB chunking) with Luhn algorithm validation (credit cards), Shannon entropy analysis (API tokens/keys), and zero-leakage redaction (`4532-••••-••••-1111`) before persistence.

⚡ **Real-Time Filesystem Telemetry**:
Continuous file observer using Python `watchdog` with a 400ms sliding-window debouncer and a thread-safe 5,000-event queue streaming live updates to the SOC via Server-Sent Events (SSE).

📊 **Explainable, Deterministic Threat Scoring (0–100)**:
"File sensitivity is context, not proof of malice." Risk scores combine primary rule weights and diminishing secondary factors, soft-capped at 100 with sliding-window repeat suppression.

🔗 **Multi-Signal Exfiltration Correlation**:
Temporally links sensitive file access, archive staging (`.zip`, `.tar`), and outbound network egress (Zeek logs, Suricata EVE alerts, and zero-leakage PCAP parsing) with explicit evidence modesty.

🤖 **Privacy-Preserving AI SOC Analyst**:
Integrates local LLMs via Ollama (`llama3.2:3b` on 6GB VRAM) and deterministic mock fallback. Features 9 bounded read-only investigation tools, indirect prompt injection defenses, and automated database entity verification to eliminate AI hallucinations.

🧪 **Cyberattack Simulation & Validation Lab**:
Built an isolated testing environment with 11 reproducible, harmless attack scenarios—achieving 100% detection precision and recall against synthetic exfiltration chains.

🔒 **Enterprise Security Hardening**:
Timing-safe RBAC (`ADMIN`, `ANALYST`, `READONLY`), 10MB payload size guards, canonical path traversal defenses (CWE-22), and production safety controls.

---

### **Engineering Numbers:**
✅ **171 automated unit/integration tests** (`pytest 8.x`) passing in ~18s (100% pass rate).  
✅ **React 18 + TypeScript 5.4 + Vite 5** dark-themed SOC operations dashboard.  
✅ **Multi-stage Docker Compose** running under unprivileged user IDs (`UID 1001`).  
✅ **100% local operation** — zero external cloud dependencies or private data leaks.  

Check out the full open-source repository, architectural diagrams, and documentation:
👉 **GitHub:** https://github.com/BULLET-USMAN/SentinelDLP

Feedback, architectural questions, and collaboration are always welcome! 💬

---

### **Hashtags**
`#Cybersecurity` `#DetectionEngineering` `#Python` `#FastAPI` `#React` `#TypeScript` `#DataLossPrevention` `#InfoSec` `#ApplicationSecurity` `#OpenSource` `#DevSecOps` `#MITREATTACK`
