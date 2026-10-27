# SentinelDLP — CI/CD Pipeline Template

This directory contains the GitHub Actions Continuous Integration pipeline specification for SentinelDLP.

## Usage
To enable automated CI runs on GitHub:
1. Ensure your GitHub Personal Access Token (or repository permissions) has the `workflow` scope enabled.
2. Copy `github-actions-ci.yml` into `.github/workflows/ci.yml`:
   ```bash
   mkdir -p .github/workflows
   cp ci/github-actions-ci.yml .github/workflows/ci.yml
   git add .github/workflows/ci.yml
   git commit -m "ci: enable github actions workflow"
   git push origin main
   ```

## Pipeline Stages
- **Backend Lint & Python 3.12 Syntax Check**: Verifies syntax compilation across all backend source files.
- **Backend Test Suite (Pytest)**: Runs all 171 automated tests in an isolated in-memory SQLite sandbox with zero external dependencies.
- **Frontend Build (TypeScript & Vite)**: Runs `tsc --noEmit` and `vite build` to guarantee zero compilation diagnostics.
- **Docker Compose Config Validation**: Validates `docker-compose.yml` service configurations and network definitions.
