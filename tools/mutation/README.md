# Mutation suites (Phase 9 M7 – M11)

These scripts check that the security tests actually catch the regressions
they are meant to catch. Each **mutation** deliberately breaks one control,
such as an authorization check, an invariant, the token handling or an audit
event. The script then runs the tests named for it, and restores the files
before moving on.

**What counts as caught:** a mutation is **caught** only if at least one of
its *named* tests fails. Unrelated failures, or a test setup error, do not
count.

**Where results go:** each script prints `CAUGHT` / `SURVIVED` per mutation,
`tree restored: True|False`, and `n/m caught`. It exits non-zero if anything
survived or the tree was not restored.

| Script | Area | Mutations | Runs |
|---|---|---|---|
| `m7_mutations.py` | Accounts, membership, last owner/admin (backend) | 24 | backend tests (PostgreSQL) |
| `m8_mutations.py` | Browser sessions, cookie, CSRF, token handling (frontend) | 32 | Vitest |
| `m9_mutations.py` | Administration console (frontend) | 25 | Vitest |
| `m10_backend_mutations.py` | Enable, global roles, own membership (backend) | 17 | backend tests (PostgreSQL) |
| `m10_frontend_mutations.py` | Account and project-role UI (frontend) | 11 | Vitest |
| `m11_backend_mutations.py` | Posture aggregates and visibility (backend) | 14 | backend tests (PostgreSQL) |
| `m11_frontend_mutations.py` | Posture dashboard rendering (frontend) | 7 | Vitest |

`m7_mutations.py` and `m8_mutations.py` also contain the runners that the
other backend and frontend scripts reuse.

## Prerequisites

The same setup as the ordinary test suites (see the main README).

- **Backend scripts:**
  - the backend environment with the scanner, analysis and reports packages
    installed;
  - PostgreSQL for the integration tests (`docker compose up -d db`).
  - The script runs `backend/.venv`'s Python if it exists, else the Python
    running it; `MUTATION_PYTHON` overrides both.
- **Frontend scripts:** `npm install` (or `npm ci`) in `frontend/`.

## Running

From the repository root, with a clean working tree:

```powershell
python tools/mutation/m7_mutations.py           # all 24
python tools/mutation/m7_mutations.py 5 19 20   # only these
python tools/mutation/m8_mutations.py
```

The backend scripts are long (tens of minutes each); the frontend ones take a
few minutes each. Backend and frontend scripts can run at the same time, since
they touch different files and only the backend uses the database. Do not run
two backend scripts at once: they share the test database.

## Safety

- **Tracked files are edited in place.** The script restores them byte for
  byte after each mutation and checks a tree hash at the end.
- **A clean tree is required.** The script refuses to start if
  `backend/app|alembic|tests` (backend scripts) or `frontend/src|tests`
  (frontend scripts) have uncommitted changes. So a run killed before it could
  restore is always undone with `git checkout -- backend frontend`.
- **Only the test database is touched.** Backend scripts use the integration
  tests' database, which must be named `…_test` (the test configuration
  refuses anything else). Mutations of a migration downgrade that test
  database afterwards; the next test run migrates it again.
- **Nothing else is touched.** No script contacts the compose stack, its
  database or the network beyond the local test database.

## In CI

`.github/workflows/mutation.yml` runs all seven scripts, on demand only
(`workflow_dispatch`).
