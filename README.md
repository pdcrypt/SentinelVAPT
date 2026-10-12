# SentinelVAPT

An **authorized** web application security assessment and reporting platform
for local security labs and explicitly authorized targets.

SentinelVAPT runs deterministic, non-destructive security checks, records
findings with evidence, supports manual triage and retesting, and generates
reports. It does not perform exploitation. See
[docs/scope-and-ethics.md](docs/scope-and-ethics.md).

> **Status:** Phase 9 (platform security, M1–M10) and M11 (security posture
> dashboard) are complete. Projects, targets with scope and
> authorization, assessments and passive discovery scans of `local_lab`
> targets are available through the REST API. A worker runs the scans, stores
> their redacted results, and analyses them offline with 14 passive rules into
> findings that can be triaged ([rule catalog](docs/rules.md)). Analysed scans
> can be turned into evidence-backed JSON, HTML and PDF reports
> ([reports](docs/reports.md)), and completed assessments can be retested and
> compared finding by finding ([retesting](docs/retesting.md)), with
> evidence-backed retest reports ([retest reports](docs/retest-reporting.md)).
> A localhost-only Next.js operator console drives the whole workflow
> ([operator console](docs/frontend.md)) behind a platform sign-in. Accounts,
> sessions, project membership and roles are enforced by the API, with audit
> logs and an administration console
> ([ADR 0014](docs/adr/0014-authentication-and-authorization.md)). Overview and
> project pages show a counts-only security posture
> ([ADR 0015](docs/adr/0015-security-posture-dashboard.md)). There are no
> active checks.

## Stack

| Part      | Tech                                         |
| --------- | -------------------------------------------- |
| Frontend  | Next.js, TypeScript, Playwright              |
| Backend   | Python, FastAPI, SQLAlchemy 2, Alembic, pytest |
| Scanner   | Standalone Python package                    |
| Analysis  | Standalone Python package (offline rules)    |
| Reports   | Standalone Python package (Jinja2, WeasyPrint) |
| Database  | PostgreSQL 17                                |
| Runtime   | Docker Compose                               |

## Repository layout

```
frontend/   Next.js operator console (talks only to the API, server-side; never contacts targets)
backend/    FastAPI API, services, repositories, models, migrations
scanner/    Scanner engine and checks (no API/DB dependencies)
analysis/   Offline rule engine: stored observations -> findings (no network/DB)
reports/    Report generation from persisted snapshots
tests/      Cross-component and lab fixture tests
tools/      Mutation suites for the security tests
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
`alembic upgrade head` before the backend, the scan `worker` and the
`report-worker` start.

To try a real scan locally, start the optional static lab target and follow
[tests/lab/README.md](tests/lab/README.md):

```powershell
docker compose --profile lab up -d
```

All ports bind to `127.0.0.1` only (see [ADR 0005](docs/adr/0005-localhost-only-until-auth.md)).

Create the first administrator once (it is refused when one exists), then
sign in at http://localhost:3000. The administrator creates the other
accounts under **Accounts** in the console; each new user sets their own
password at first sign-in. There is no self-registration. Project owners add
members under the project's **Members** tab, and read its **Audit log**;
administrators read the **Platform audit log**, enable disabled accounts again
and change an account's global role (never their own; the platform always
keeps an active administrator). Every project page shows your own role in it.

```powershell
docker compose exec backend python -m app.cli create-admin --username admin --display-name "Administrator"
```

## Demo workflow (operator console)

Authorized local lab use only. Open http://localhost:3000 with the lab target
running (`docker compose --profile lab up -d`) and sign in, then:

1. **Projects:** create a project. **Add target:**
   - base URL `http://lab-target/`, in-scope host `lab-target`;
   - record the authorization and tick the acknowledgement. The platform
     records that you, the signed-in user, acknowledged it, but it cannot
     verify that the authorization itself is genuine.
2. On the target, **plan an assessment**, **start** it and **launch a passive
   scan**. The scan page refreshes until the scan and its analysis finish.
3. **Findings:** open them with their evidence (shown as inert text). Record a
   **triage** decision.
4. **Request a scan report:** download JSON, HTML or PDF, or preview the HTML
   in a sandboxed frame.
5. **Complete the assessment**, **create a retest**, scan it, and **request a
   comparison**.
   - Every finding gets a stored comparison state (`FIXED`, `NOT_RETESTED`, …)
     with its reasons and coverage evidence.
   - Triage is shown separately.
   - Against an unchanged lab every record is `UNCHANGED`. To see `FIXED`,
     `NEW`, `DISMISSED` and `REOPENED`, switch the lab's header variant between
     scans (lab only):
     [tests/lab/README.md](tests/lab/README.md#retest-walkthrough-fixed-new-dismissed-reopened).
6. From the comparison, **request a retest report**.
7. **Overview and project pages** show the security posture computed by the
   API from those records: current findings by severity and triage status,
   the latest retest outcome (`FIXED`, `NEW`, `REOPENED`, …), the latest
   reports and recent scans. Counts only; there is no score
   ([ADR 0015](docs/adr/0015-security-posture-dashboard.md)).

The browser talks only to the console; the API stays server-side. The
console's design and threat model are in [docs/frontend.md](docs/frontend.md)
and [ADR 0013](docs/adr/0013-frontend-architecture-and-threat-model.md). AI is
not used anywhere in the deterministic pipeline.

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
# The backend imports the scanner, the rule engine and the report renderer.
# Install them from this repository first; they are deliberately not declared
# dependencies, so pip never fetches a same-named package from PyPI. (compat
# mode lets mypy see the editable installs.)
.\.venv\Scripts\python -m pip install -e ..\scanner --config-settings editable_mode=compat
.\.venv\Scripts\python -m pip install -e ..\analysis --config-settings editable_mode=compat
.\.venv\Scripts\python -m pip install -e ..\reports --config-settings editable_mode=compat
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m alembic upgrade head
.\.venv\Scripts\python -m uvicorn --factory app.main:create_app --reload
# In another terminal, the worker (scans, analysis and reports; use
# --role scans / --role reports to split them as compose does):
.\.venv\Scripts\python -m app.worker
```

PDF reports need WeasyPrint's system libraries (Pango, HarfBuzz). They are in
the Docker image and installed in CI; on Windows, install them separately (see
the WeasyPrint documentation) or generate PDFs through `docker compose`. Without
them, JSON and HTML reports still work and PDF tests are skipped locally.

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
npm run test:unit                 # Vitest: security guards, API client, rendering, charts
npm run api:check                 # generated API types match the OpenAPI snapshot
npx playwright install chromium   # once
npm run test:e2e                  # builds and starts a production server; live-stack tests skip
```

**End-to-end against the running compose stack:** this runs the whole
A → B → C workflow through the UI. It needs Docker, because it starts a
temporary nginx lab target on the compose network.

```powershell
$env:E2E_BASE_URL = "http://localhost:3000"; npm run test:e2e
Remove-Item Env:E2E_BASE_URL
```

**Mutation suites** (`tools/mutation/`): scripts that break one security control
at a time and check that a named test catches it. They need a clean working
tree; see [tools/mutation/README.md](tools/mutation/README.md).

**CI** (`.github/workflows/`): `ci.yml` runs on pushes to `main` and on pull
requests. It has three jobs:

- the Python checks for each package;
- the frontend checks;
- `e2e-live`: the live-stack Playwright specs, including the lab retest,
  against a compose stack built on the runner. It uses a fresh database
  volume and credentials generated for the run, and removes everything
  afterwards.

`mutation.yml` runs the mutation suites on demand (`workflow_dispatch`).
Neither workflow has run on GitHub yet, so there is no CI result for either.

## Configuration

All configuration and secrets come from environment variables, and
`.env.example` lists every variable the application and its tests read. `.env`
is git-ignored. Nothing secret is hard-coded, and required secrets have no
defaults: the backend refuses to start without them.

- **Docker Compose** reads `.env` for the values it substitutes into
  `docker-compose.yml`. Only the variables named there reach the containers:
  `APP_ENV`, `LOG_LEVEL` and `DATABASE_URL` for the backend and workers,
  `CORS_ORIGINS` for the backend, `DATABASE_URL` for the migration job, and
  `API_INTERNAL_URL` for the frontend.
- **The backend run natively** also reads the repo-root `.env`, including the
  optional, bounded `AUTH_*` and `WORKER_*` settings.
- **The frontend run natively** reads only its own environment (the shell, or
  `frontend/.env.local`): `API_INTERNAL_URL`, `FRONTEND_ALLOWED_HOSTS` and,
  on a development server only, `SESSION_COOKIE_INSECURE`.
- **Test-only variables** (`TEST_DATABASE_URL`, `REQUIRE_PDF`, `E2E_*`) are
  listed at the end of `.env.example` and are not runtime configuration.

## Roadmap

| Phase | Scope                                                              |
| ----- | ------------------------------------------------------------------ |
| 0 ✅  | Foundation: monorepo, compose, config, tooling, docs               |
| 1 ✅  | Core domain: projects, targets with authorization, assessments     |
| 2 ✅  | Discovery engine: scan grants, scope guard, safe HTTP client       |
| 3 ✅  | Scan execution: worker, scan logs, assets, endpoints, evidence     |
| 4 ✅  | Analysis: offline rule engine, findings, triage API                |
| 5 ✅  | Reporting: snapshot-based JSON / HTML / PDF reports                |
| 6 ✅  | Retesting: retest chains, evidence-backed scan comparison          |
| 7 ✅  | Retest reports: comparison-based JSON / HTML / PDF reports         |
| 8 ✅  | Operator console: localhost-only Next.js UI for the whole workflow |
| 9 ✅  | Platform security (M1–M10): accounts, sessions, roles, actors, audit, administration |
| M11 ✅ | Security posture dashboard ([ADR 0015](docs/adr/0015-security-posture-dashboard.md)) |

PDF reports have been part of reporting since Phase 5. Phase 9's milestones
are listed in [ADR 0014](docs/adr/0014-authentication-and-authorization.md).
The manual retest walkthrough with lab header variants is in
[tests/lab/README.md](tests/lab/README.md#retest-walkthrough-fixed-new-dismissed-reopened).

Not done yet: neither GitHub Actions workflow (`ci.yml`, `mutation.yml`) has
run on GitHub, and a clean-clone smoke test of the quick start has not been
carried out.
