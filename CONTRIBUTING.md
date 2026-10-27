# Contributing to SentinelDLP

Thank you for your interest in contributing to **SentinelDLP**! We welcome contributions from cybersecurity engineers, detection researchers, and software developers who share our commitment to defensive security, zero-leakage privacy, and reliable software engineering.

---

## 1. Defensive Security & Ethical Standards

SentinelDLP is strictly a **defensive Data Loss Prevention and threat detection platform**. We operate under strict ethical cybersecurity guidelines:
- **No Offensive Exploits**: Submissions containing live exploit payloads, weaponized malware binaries, unconstrained network scanners, or malicious payloads will be rejected.
- **Harmless Validation Only**: Any attack simulation or detection validation fixtures must remain entirely synthetic, harmless, and strictly isolated to designated sandbox directories (`sample_data/simulation_lab/`).
- **Telemetry Modesty**: Code must never fabricate telemetry, synthetic process IDs, or unverified user attribution. Modesty disclosures must be maintained across all detections.

---

## 2. Development Setup

### Prerequisites
- **Python:** 3.12 or higher
- **Node.js:** 20.x or higher with `npm`
- **PostgreSQL:** 16.x (or SQLite for local test executions)
- **Git:** 2.40+

### Setup Steps
```powershell
# 1. Fork and clone the repository
git clone https://github.com/BULLET-USMAN/SentinelDLP.git
cd SentinelDLP

# 2. Backend virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt

# 3. Frontend dependencies
cd frontend
npm install
cd ..

# 4. Copy configuration template
Copy-Item .env.example .env
```

---

## 3. Git Branching & Commit Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

### Branch Naming
- `feat/feature-name` — New detection rules, telemetry adapters, or UI consoles.
- `fix/bug-description` — Bug fixes or security vulnerability remediation.
- `docs/doc-update` — Architectural documentation or release notes.
- `refactor/component-name` — Code restructuring without functional changes.
- `test/test-description` — Test coverage expansion.

### Commit Messages
Format: `<type>(<scope>): <subject>`

Examples:
- `feat(detection): add entropy evaluation for dns tunneling (NET-005)`
- `fix(scanner): resolve symlink escape boundary check on Windows paths`
- `docs(architecture): add sequence diagram for AI tool execution`
- `chore(release): bump version to 1.0.0`

---

## 4. Coding Standards

### Backend (Python)
- Follow **PEP 8** style guidelines.
- Use explicit type annotations for all function signatures and return types.
- Ensure all datetimes use modern timezone-aware UTC (`datetime.now(timezone.utc)`).
- Handle database sessions safely using asynchronous context managers (`get_db_session`).
- Strictly sanitize and mask all sensitive data patterns prior to database persistence.

### Frontend (TypeScript / React)
- Strict mode is enforced in `tsconfig.json`. No implicit `any` types.
- Maintain the cybersecurity dark theme color palette (`#0a0e17` slate background, `#10b981` emerald, `#f59e0b` amber, `#ef4444` rose).
- Use `lucide-react` for consistent, accessible iconography.
- Handle loading states, empty states, and API error boundaries gracefully.

---

## 5. Testing & Verification Requirements

No pull request will be merged without passing automated test verification:
1. **Backend Tests:** Run the complete pytest test suite:
   ```powershell
   .\.venv\Scripts\python.exe -m pytest -q
   ```
   All tests must pass (171+ tests) with zero failures.
2. **Frontend Build:** Verify TypeScript compilation and production bundling:
   ```powershell
   cd frontend
   npm run build
   ```
   Must compile with 0 TypeScript diagnostics and produce production bundles in `dist/`.
3. **Linting & Code Quality:** Ensure no unhandled exceptions or unresolved imports exist.

---

## 6. Pull Request Review Checklist

Before opening a pull request, ensure you have completed the following:
- [ ] Code follows defensive guidelines and contains no offensive or live malware payloads.
- [ ] Added comprehensive unit/integration tests covering new or modified functionality.
- [ ] All automated tests pass (`pytest -q` returns 100% pass rate).
- [ ] Frontend builds cleanly with zero TypeScript errors (`npm run build`).
- [ ] Relevant documentation in `docs/` or `README.md` has been updated.
- [ ] Sensitive findings and credentials are masked before storage/display.
- [ ] Telemetry modesty disclosures are maintained for new detection signals.

---

## 7. Responsible Vulnerability Disclosure

If you discover a security vulnerability in SentinelDLP, please do **NOT** open a public issue. Instead, report it responsibly:
- Email the security maintainers at: `security@sentineldlp.local` (or submit a private GitHub Security Advisory).
- Provide a detailed description of the vulnerability, reproduction steps, and potential impact.
- We will acknowledge receipt within 48 hours and work with you on a coordinated fix.
