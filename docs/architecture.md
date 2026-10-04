# Architecture

## Components

```
frontend (Next.js) ──HTTP──▶ backend API (FastAPI) ──SQL──▶ PostgreSQL
                                                             ▲
                              worker (backend package) ──────┘
                                  │ calls a pure Python API
                                  ▼
                              scanner (standalone) ──scoped HTTP──▶ lab / authorized targets

reports (standalone) renders persisted assessment snapshots.
```

| Component  | Owns                                                                   | Must never                                     |
| ---------- | ---------------------------------------------------------------------- | ---------------------------------------------- |
| `frontend` | UI, triage workflow, report download                                   | Contact targets, hold secrets                  |
| `backend`  | CRUD, validation, authorization/scope rules, enqueueing scans          | Perform network scanning                       |
| worker     | Claim queued scans, call the scanner, persist results                  | Bypass the scanner's scope guard               |
| `scanner`  | Checks, scope enforcement, safe HTTP client, finding candidates        | Import backend code, touch the DB, read env    |
| `reports`  | Build report snapshots, render HTML (PDF later)                        | Trigger scans or modify findings               |

## Backend layering

`api/v1/routers` → `services` → `repositories` → `models`

- Routers handle HTTP only (parsing, status codes).
- Services hold business rules and depend on repositories, not on FastAPI.
- Repositories are the only layer issuing queries; they take an injected
  `Session`, so tests can supply a test database session or a fake.
- `core/config.py` reads all configuration from environment variables.

## Data flow: target → scan → finding → report

1. A target is created with scope and authorization fields.
2. An assessment is created for the target.
3. Starting a scan re-validates authorization and stores a frozen
   `scope_snapshot` on a `queued` scan row.
4. The worker claims the scan (`FOR UPDATE SKIP LOCKED`) and calls the scanner.
5. The scanner validates each request against scope, runs checks and returns
   finding candidates with redacted evidence.
6. The worker upserts assets/endpoints and matches findings by `fingerprint`.
7. Findings are triaged in the UI.
8. Reports render from an immutable snapshot stored with a content hash.
9. Retests are child assessments; fingerprint diffs show fixed, still present
   and new findings.

## Domain model

```
Project 1─N Target 1─N Asset 1─N Endpoint
Project 1─N Assessment N─1 Target   (Assessment.parent_assessment_id → retests)
Assessment 1─N Scan 1─N ScanLog
Scan 1─N Finding 1─N Evidence
Assessment 1─N Report
```

Findings carry `detection_type`: `automated_detection` or
`manual_verification_required`.

See [`adr/`](adr/) for the reasoning behind key decisions and
[`scope-and-ethics.md`](scope-and-ethics.md) for safety boundaries.
