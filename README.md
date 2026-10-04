# SentinelVAPT

An **authorized** web application security assessment and reporting platform
for local security labs and explicitly authorized targets.

SentinelVAPT runs deterministic, non-destructive security checks, records
findings with evidence, supports manual triage and retesting, and generates
reports. It does not perform exploitation. See
[docs/scope-and-ethics.md](docs/scope-and-ethics.md).

> **Status:** Phase 4 (deterministic analysis). Projects, targets with scope
> and authorization, assessments and passive discovery scans of `local_lab`
> targets are available through the REST API. A worker runs the scans, stores
> their redacted results, and analyses them offline with 14 passive rules into
> findings that can be triaged through the API
> ([rule catalog](docs/rules.md)). There are no active checks, no reports and
> no UI yet.

## Stack

| Part      | Tech                                         |
| --------- | -------------------------------------------- |
| Frontend  | Next.js, TypeScript, Playwright              |
| Backend   | Python, FastAPI, SQLAlchemy 2, Alembic, pytest |
| Scanner   | Standalone Python package                    |
| Analysis  | Standalone Python package (offline rules)    |
| Reports   | Standalone Python package                    |
| Database  | PostgreSQL 17                                |
| Runtime   | Docker Compose                               |

## Repository layout

```
frontend/   Next.js app (UI only; never contacts targets)
backend/    FastAPI API, services, repositories, models, migrations
scanner/    Scanner engine and checks (no API/DB dependencies)
analysis/   Offline rule engine: stored observations -> findings (no network/DB)
reports/    Report generation from persisted snapshots
tests/      Cross-component and lab fixture tests
docs/       Architecture, ADRs, scope and ethics, per-check docs
```

More detail: [docs/architecture.md](docs/architecture.md) and the
[architecture decision records](docs/adr/).

## Quick start (Docker)

Commands below are for Windows PowerShell, run from the repo root unless noted.

```powershell
Copy-Item .env.example .env   # then set a real POSTGRES_PASSWORD (and the same value in DATABASE_URL)
docker compose up --build
```

- Frontend: http://localhost:3000
- API health: http://localhost:8000/api/v1/health
- API docs (non-production): http://localhost:8000/docs

Migrations run automatically: a one-shot `migrate` service applies
`alembic upgrade head` before the backend and the scan `worker` start.

To try a real scan locally, start the optional static lab target and follow
[tests/lab/README.md](tests/lab/README.md):

```powershell
docker compose --profile lab up -d
```

All ports bind to `127.0.0.1` only (see [ADR 0005](docs/adr/0005-localhost-only-until-auth.md)).

## Local development

Run PostgreSQL in Docker and the apps natively:

```powershell
docker compose up -d db
```

The Python commands call the virtual environment's interpreter directly
(`.\.venv\Scripts\python`), so you don't need to activate it. This also avoids
PowerShell's default execution policy blocking `Activate.ps1`.

**Backend:**

```powershell
cd backend
python -m venv .venv
# The backend imports the scanner and the rule engine. Install them from this
# repository first; they are deliberately not declared dependencies, so pip
# never fetches a same-named package from PyPI. (compat mode lets mypy see the
# editable installs.)
.\.venv\Scripts\python -m pip install -e ..\scanner --config-settings editable_mode=compat
.\.venv\Scripts\python -m pip install -e ..\analysis --config-settings editable_mode=compat
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m alembic upgrade head
.\.venv\Scripts\python -m uvicorn --factory app.main:create_app --reload
# In another terminal, the scan worker:
.\.venv\Scripts\python -m app.worker
```

The backend reads `DATABASE_URL` and other settings from environment variables,
falling back to the repo-root `.env`. Outside Docker, use the `127.0.0.1` form
of `DATABASE_URL` from `.env.example`.

After changing models, generate a migration and review it before applying:

```powershell
.\.venv\Scripts\python -m alembic revision --autogenerate -m "describe the change"
```

**Scanner / analysis / reports** (same steps in `scanner\`, `analysis\` or `reports\`):

```powershell
cd scanner
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
```

**Frontend:**

```powershell
cd frontend
npm install
npm run dev
```

On macOS/Linux, use `.venv/bin/python` instead of `.\.venv\Scripts\python`.

## Checks and tests

**Python** (in `backend\`, `scanner\`, `analysis\` or `reports\`):

```powershell
.\.venv\Scripts\python -m ruff check .
.\.venv\Scripts\python -m ruff format --check .
.\.venv\Scripts\python -m mypy .
.\.venv\Scripts\python -m pytest
```

Backend integration tests need PostgreSQL (`docker compose up -d db`). They use
a separate database, `DATABASE_URL`'s name plus `_test` (or `TEST_DATABASE_URL`),
build it with the real migrations and roll back after every test. They are
skipped locally if PostgreSQL is unreachable, and fail in CI. For the fast unit
tests only: `.\.venv\Scripts\python -m pytest tests\unit`.

**Frontend** (in `frontend\`):

```powershell
npm run lint
npm run typecheck
npm run format:check
npx playwright install chromium   # once
npm run test:e2e                  # starts a dev server automatically
```

**End-to-end against the running compose stack:**

```powershell
$env:E2E_BASE_URL = "http://localhost:3000"; npm run test:e2e
Remove-Item Env:E2E_BASE_URL
```

CI runs the Python and frontend checks on every push to `main` and on every
pull request (`.github/workflows/ci.yml`).

## Configuration

All configuration and secrets come from environment variables. `.env.example`
documents every variable; `.env` is git-ignored. Nothing secret is hard-coded,
and required secrets have no defaults: the backend refuses to start without
them.

## Roadmap

| Phase | Scope                                                              |
| ----- | ------------------------------------------------------------------ |
| 0 ✅  | Foundation: monorepo, compose, config, tooling, docs               |
| 1 ✅  | Core domain: projects, targets with authorization, assessments     |
| 2 ✅  | Discovery engine: scan grants, scope guard, safe HTTP client       |
| 3 ✅  | Scan execution: worker, scan logs, assets, endpoints, evidence     |
| 4 ✅  | Analysis: offline rule engine, findings, triage API                |
| 5     | Reporting: HTML reports from snapshots                             |
| 6     | Retesting: fixed / still present / new diffs                       |
| 7     | Frontend MVP: target/assessment flows, live scans, triage          |
| 8     | Hardening: platform auth, more checks, PDF export, polish          |
