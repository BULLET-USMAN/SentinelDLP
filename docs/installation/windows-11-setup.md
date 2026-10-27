# SentinelDLP — Windows 11 Installation & Setup Guide

This guide provides reproducible, step-by-step instructions for installing and running **SentinelDLP v1.0.0** on Windows 11.

---

## 1. Environment & Prerequisites

Tested configuration:
- **Operating System:** Windows 11 Pro / Home (64-bit)
- **CPU:** AMD Ryzen 5 5600 / Intel Core i5 (or equivalent)
- **RAM:** 16 GB recommended (4 GB minimum)
- **GPU:** Optional NVIDIA RTX 2060 (6GB VRAM) for local Ollama LLM acceleration

### Required Tools
1. **Python 3.12+**: Download from [python.org](https://www.python.org/downloads/). Ensure **"Add Python to PATH"** is checked.
2. **Node.js 20+ LTS**: Download from [nodejs.org](https://nodejs.org/).
3. **PostgreSQL 16**: Download from [postgresql.org](https://www.postgresql.org/download/windows/) (or use Docker Compose).
4. **Git**: Download from [git-scm.com](https://git-scm.com/).

---

## 2. Clone & PowerShell Policy

Open Windows PowerShell (Run as Administrator or standard user):

```powershell
# Set PowerShell Execution Policy (if running scripts is restricted)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Clone repository
git clone https://github.com/BULLET-USMAN/SentinelDLP.git
cd SentinelDLP
```

---

## 3. Backend Setup

### Create Python Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Install Backend Dependencies
```powershell
pip install --upgrade pip
pip install -r backend/requirements.txt
```

### Configure Environment Variables
```powershell
Copy-Item .env.example .env
```
*(The default `.env` is pre-configured for local demonstration with testing SQLite/PostgreSQL fallbacks and the deterministic Mock AI Provider).*

### Run Database Migrations
```powershell
.\.venv\Scripts\alembic.exe upgrade head
```

---

## 4. Frontend Setup

Open a separate PowerShell terminal or navigate to the `frontend` folder:

```powershell
cd frontend
npm install
cd ..
```

---

## 5. Verify Installation (Automated Test Suite)

Before starting the servers, execute the automated test suite to verify all 12 platform subsystems:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```
**Expected Output:**
```
171 passed, 3 warnings in ~18s
```

---

## 6. Launching SentinelDLP

### Option A: One-Click PowerShell Launcher
```powershell
.\scripts\run_local.ps1
```
This launches both the FastAPI backend on port 8000 and the Vite frontend on port 5173.

### Option B: Manual Launch (Two Terminals)

**Terminal 1 (Backend API):**
```powershell
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

**Terminal 2 (Frontend UI):**
```powershell
cd frontend
npm run dev
```

---

## 7. Verify Health & Operations

Run the automated health check script:
```powershell
.\scripts\verify_health.ps1
```

Access the interfaces:
- **SOC Executive Dashboard:** `http://localhost:5173`
- **AI SOC Analyst Console:** `http://localhost:5173/ai-analyst`
- **Security Testing Laboratory:** `http://localhost:5173/security-lab`
- **FastAPI OpenAPI Swagger:** `http://127.0.0.1:8000/docs`

---

## 8. (Optional) Enabling Local Ollama LLM Acceleration

By default, SentinelDLP uses the zero-resource **Deterministic Mock Provider**. To enable real local LLM analysis via Ollama:

1. Download Ollama for Windows from [ollama.com](https://ollama.com/).
2. Pull the optimized 3B parameter security model:
   ```powershell
   ollama pull llama3.2:3b
   ```
3. Update your `.env` configuration:
   ```ini
   AI_PROVIDER=ollama
   OLLAMA_BASE_URL=http://localhost:11434
   OLLAMA_MODEL=llama3.2:3b
   ```
4. Restart the backend service. SentinelDLP will automatically route investigations to your local GPU.
