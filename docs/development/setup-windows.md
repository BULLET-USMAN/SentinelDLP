# Windows 11 Local Development Setup Guide

This guide details the step-by-step setup procedure for running SentinelDLP on Windows 11.

---

## 1. Prerequisites

Verify installed tools via PowerShell:

```powershell
python --version    # Requires Python 3.11+ (Tested on Python 3.12.10)
node --version      # Requires Node.js 18+ (Tested on v24.21.0)
npm.cmd --version   # Requires npm 9+
git --version       # Requires Git 2.30+
```

> **Note on PowerShell Script Execution:**
> If PowerShell blocks `npm` with `PSSecurityException`, use `npm.cmd` directly or run:
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

---

## 2. Setting Up Backend (Python)

1. **Create and activate a virtual environment**:
   ```powershell
   cd E:\Downloads\Projects\SentinelDLP
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. **Install backend dependencies**:
   ```powershell
   .\.venv\Scripts\pip.exe install -r backend\requirements.txt
   ```

3. **Configure Environment Variables**:
   ```powershell
   Copy-Item .env.example .env
   ```
   *(Update `.env` with your desired settings or leave local defaults)*

4. **Verify Backend Tests**:
   ```powershell
   .\.venv\Scripts\python.exe -m pytest -v backend\tests
   ```

5. **Start Backend Server**:
   ```powershell
   .\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --port 8000 --host 127.0.0.1 --reload
   ```
   API Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
   Liveness Probe: [http://127.0.0.1:8000/health/live](http://127.0.0.1:8000/health/live)

---

## 3. Setting Up Frontend (React + Vite)

1. **Navigate to the frontend directory**:
   ```powershell
   cd frontend
   ```

2. **Install frontend dependencies**:
   ```powershell
   npm.cmd install
   ```

3. **Build or Start Dev Server**:
   ```powershell
   # Start dev server:
   npm.cmd run dev
   # Or build production bundle:
   npm.cmd run build
   ```
   Frontend App: [http://localhost:5173](http://localhost:5173)

---

## 4. Database Migrations (Alembic)

To preview generated SQL without connecting to PostgreSQL (offline mode):
```powershell
cd backend
..\.venv\Scripts\alembic.exe upgrade head --sql
```

When local PostgreSQL (or Docker PostgreSQL) is running:
```powershell
cd backend
..\.venv\Scripts\alembic.exe upgrade head
```

---

## 5. One-Click Development Launcher

Use the provided PowerShell script in the root directory:
```powershell
.\scripts\run_local.ps1
```
