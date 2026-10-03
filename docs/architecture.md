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
4. The worker claims the scan (`FOR UPDATE SKIP LOCKED`), builds a `ScanGrant`
   and calls the scanner.
5. The scanner re-validates the grant, checks every request against scope, and
   returns redacted discovery results (and, later, finding candidates).

Steps 1–5 exist (Phases 1–3: scans are queued by the API and run by the
worker, ADR 0008); steps 6–9 (findings, triage, reports, retests) are later
phases.

## Domain model

```
Project 1─N Target 1─N TargetAuthorization  (implemented, Phase 1; append-only)
Target 1─N Assessment N─1 TargetAuthorization (implemented, Phase 1)
Assessment 1─N Scan (implemented, Phase 3; scan → its assessment's target + authorization)
Scan 1─N ScanLog, Asset, Endpoint, Evidence   (implemented, Phase 3; scan-scoped)
Endpoint 1─N EndpointCookie, Evidence         (implemented, Phase 3)
Scan 1─N Finding                             (planned)
Assessment 1─N Report                       (planned)
Assessment.parent_assessment_id → retests   (planned, Phase 6)
```

An assessment reaches its project through its target; there is no separate
`project_id` on assessments. Foreign keys use `ON DELETE RESTRICT`: the API
refuses (409) to delete a project with targets or a target with assessments.

A target's scope and authorization live in **append-only `TargetAuthorization`
records** ([ADR 0006](adr/0006-append-only-target-authorizations.md)). Each
record holds the acknowledged scope plus who authorized it, the reference,
the validity window and who acknowledged it when. `targets.current_authorization_id`
points at the record in force; `assessments.authorization_id` records the one an
assessment was planned under. Composite foreign keys guarantee both belong to
the same target, and a trigger rejects any UPDATE of a record or any DELETE
other than the cascade from deleting a whole target (allowed only while it has
no assessments).

Findings will carry `detection_type`: `automated_detection` or
`manual_verification_required`.

### Target scope and authorization (Phase 1)

Validated in `backend/app/services/scope.py` (pure functions) and enforced by
`TargetService`; database CHECK constraints are a backstop.

- **Scope** is an allowlist: explicit hosts (no wildcards or CIDR ranges),
  ports (default: the base URL's port), path prefixes and excluded paths. The
  base URL must fall inside it and must not contain credentials, a query or a
  fragment; an explicit port must be 1–65535. Link-local addresses (e.g.
  `169.254.169.254`), IPv6 zone IDs, and hostnames that a resolver or URL
  parser could read as a numeric IP (`0xa9fea9fe`, `2852039166`, `127.1`, any
  host whose last label is numeric) are always rejected.
- **`local_lab`** targets may only use loopback/private IPs, `localhost`,
  single-label names (docker service names) or lab suffixes such as `.test`
  and `.local`. Hostnames are checked by name only, offline; resolved addresses
  are re-checked by the scanner at request time (Phase 2).
- **Authorization** records who authorized testing, a reference, a validity
  window and an explicit `acknowledge: true` (a JSON boolean; `1` is rejected).
  `acknowledged_at` is set by the server. Changing any scope field requires a
  new authorization in the same request; renaming does not. Every
  re-authorization appends a record with the next version.
- **Concurrency.** Target updates lock the target row (`SELECT … FOR UPDATE`),
  read the current state after acquiring the lock, and validate the complete
  resulting state before writing, so concurrent edits serialize instead of
  combining stale fields. Duplicate names that slip past the service check are
  stopped by unique constraints (409, no SQL details returned).
- **Assessment status** moves `planned → in_progress → completed`, or to
  `cancelled` from either non-terminal state, through explicit `start`,
  `complete` and `cancel` actions. Creating one requires the current
  authorization not to have expired. Starting requires it to be active *and*
  to still be the record the assessment was planned under; after a
  re-authorization, plan a new assessment.

## Scanner (Phase 2: discovery engine)

A standalone package (`scanner/sentinel_scanner`) with no runtime
dependencies. The backend will call one function:

```python
run_discovery(grant: ScanGrant, config: DiscoveryConfig | None = None, *,
              cancel: CancellationToken | None = None,
              on_event: Callable[[ScanEvent], None] | None = None) -> DiscoveryResult
```

| Module | Role |
| ------ | ---- |
| `grant.py` | `ScanGrant` contract; `validate_grant()` refuses before any I/O |
| `scope.py` | `ScopePolicy`: URL check on the canonical path; resolved-address check |
| `netaddr.py` | IP policy incl. IPv4 embedded in IPv6 |
| `resolver.py` | `Resolver` protocol; system resolver with timeout; static resolver for tests |
| `transport.py` | `SafeHttpClient`: the only module that opens connections |
| `limits.py`, `ratelimit.py` | Limits with hard caps; request spacing |
| `redaction.py` | Masking of headers, cookies, URLs, body excerpts |
| `discovery/` | Link/robots/sitemap extraction, cookie flags, technology hints, crawler |
| `models.py` | `DiscoveryResult` and its parts, `to_dict()`, `schema_version` |

See [ADR 0007](adr/0007-scanner-network-boundary.md) for the security
boundary and [checks/discovery.md](checks/discovery.md) for exactly what is
requested.

## Scan execution (Phase 3)

See [ADR 0008](adr/0008-scan-execution-and-worker.md). In short:

- `POST /assessments/{id}/scans` checks the same rules the worker applies
  (assessment `in_progress`, authorization current, active and `local_lab`,
  scanner grant validation, no other active scan) and inserts a `queued` scan.
- The worker (`python -m app.worker`, compose service `worker`) claims it under
  locks **assessment → target → scan**, builds the `ScanGrant` from those rows,
  records `grant_snapshot` (audit only), runs the scanner with no database
  session open, and writes all results plus the final status in one
  transaction.
- States: `queued → running → completed | cancelled | failed`. A watcher
  cancels a running scan when cancel is requested, the assessment leaves
  `in_progress` or the target is re-authorized; a reaper fails scans whose
  worker stopped sending heartbeats. No automatic retries.
- Results are normalized, scan-scoped tables (`scan_logs`, `assets`,
  `endpoints`, `endpoint_cookies`, `evidence`) with unique keys that make
  re-persisting a no-op.

## API (v1)

| Method | Path |
| ------ | ---- |
| `GET` | `/api/v1/health`, `/api/v1/health/ready` |
| `POST`, `GET` | `/api/v1/projects` |
| `GET`, `PATCH`, `DELETE` | `/api/v1/projects/{id}` |
| `POST`, `GET` | `/api/v1/projects/{id}/targets` |
| `GET` | `/api/v1/projects/{id}/assessments` |
| `GET`, `PATCH`, `DELETE` | `/api/v1/targets/{id}` |
| `GET` | `/api/v1/targets/{id}/authorizations` (history, newest first) |
| `POST`, `GET` | `/api/v1/targets/{id}/assessments` |
| `GET`, `PATCH`, `DELETE` | `/api/v1/assessments/{id}` |
| `POST` | `/api/v1/assessments/{id}/start`, `/complete`, `/cancel` |
| `POST`, `GET` | `/api/v1/assessments/{id}/scans` (body: `{"allow_untrusted_tls": false}`) |
| `GET` | `/api/v1/scans/{id}` |
| `POST` | `/api/v1/scans/{id}/cancel` |
| `GET` | `/api/v1/scans/{id}/logs`, `/assets`, `/endpoints` (filters: `fetched`, `skip_reason`, `source`, `method`), `/evidence` |
| `GET` | `/api/v1/evidence/{id}` |

Errors from business rules return `{"detail", "code", "field"}` with 404
(`not_found`), 409 (`conflict`, `invalid_state_transition`,
`target_authorization_invalid`) or 422 (`validation_error`). Interactive docs
are at `/docs` outside production.

See [`adr/`](adr/) for the reasoning behind key decisions and
[`scope-and-ethics.md`](scope-and-ethics.md) for safety boundaries.
