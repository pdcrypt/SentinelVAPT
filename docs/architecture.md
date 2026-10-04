# Architecture

## Components

```
frontend (Next.js) ──HTTP──▶ backend API (FastAPI) ──SQL──▶ PostgreSQL
                                                             ▲
                              worker (backend package) ──────┘
                                  │ calls a pure Python API
                                  ▼
                              scanner (standalone) ──scoped HTTP──▶ lab / authorized targets

worker ──plain values──▶ analysis (standalone, offline rule engine) ──▶ finding candidates

report-worker (backend package, role "reports") ──frozen snapshot──▶ reports (standalone,
                                               offline renderer) ──▶ JSON / HTML / PDF
```

| Component  | Owns                                                                   | Must never                                     |
| ---------- | ---------------------------------------------------------------------- | ---------------------------------------------- |
| `frontend` | Operator console: whole workflow, triage, reports (server-side API client) | Contact targets, hold secrets, expose the API to the browser |
| `backend`  | CRUD, validation, authorization/scope rules, enqueueing scans          | Perform network scanning                       |
| worker     | Claim queued scans, call the scanner, persist results, run analysis and retest comparisons | Bypass the scanner's scope guard |
| report-worker | Claim queued reports and retest reports, render them, store the artifacts | Reach anything but the database                |
| `scanner`  | Discovery, scope enforcement, safe HTTP client, redaction              | Import backend code, touch the DB, read env    |
| `analysis` | Deterministic rules: stored observations → finding candidates          | Make network requests, touch the DB, use AI    |
| `reports`  | Validate snapshots, render JSON / HTML / PDF from them                 | Fetch resources, touch the DB, import backend/scanner/analysis |

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
   returns redacted discovery results, which the worker persists.
6. The worker analyses the persisted results offline with the rule engine and
   stores findings that reference the existing evidence.
7. Findings are triaged through the API.
8. A report request freezes a snapshot of one analysed scan; the report worker
   renders it into JSON, HTML and PDF artifacts.
9. A retest (a new assessment linked to a completed one and one of its analysed
   scans) is scanned like any assessment; a comparison classifies its findings
   against that baseline from persisted data.
10. A retest report request freezes a snapshot of one completed comparison
    (states copied, never recomputed); the report worker renders it.

Steps 1–10 exist (Phases 1–7; ADR 0008, 0009, 0010, 0011, 0012). The
operator console (Phase 8, ADR 0013) drives all of them from the browser.

## Domain model

```
Project 1─N Target 1─N TargetAuthorization  (implemented, Phase 1; append-only)
Target 1─N Assessment N─1 TargetAuthorization (implemented, Phase 1)
Assessment 1─N Scan (implemented, Phase 3; scan → its assessment's target + authorization)
Scan 1─N ScanLog, Asset, Endpoint, Evidence   (implemented, Phase 3; scan-scoped)
Endpoint 1─N EndpointCookie, Evidence         (implemented, Phase 3)
Scan 1─N AnalysisRun 1─N Finding             (implemented, Phase 4)
Finding N─M Evidence (same scan only)        (implemented, Phase 4)
Finding 1─N FindingStatusChange              (implemented, Phase 4; triage history)
RuleVersion 1─N Finding                      (implemented, Phase 4; immutable metadata)
Assessment 1─N Report N─1 Scan, AnalysisRun  (implemented, Phase 5; immutable snapshot)
Report 1─N ReportArtifact                    (implemented, Phase 5; json/html/pdf, hashed)
Report N─M Finding, Evidence (same scan)     (implemented, Phase 5; report_findings/_evidence)
Assessment.retest_of_assessment_id → parent  (implemented, Phase 6; same target, immutable)
Assessment.baseline_scan_id → parent's scan  (implemented, Phase 6; immutable)
Assessment(retest) 1─N Comparison            (implemented, Phase 6; one per scan and policy)
Comparison 1─N ComparisonRecord 1─N coverage evidence (current scan only)
User 1─1 UserCredential, User 1─N Session      (schema only, Phase 9 M1)
Project N─M User via ProjectMember(role)      (schema only, Phase 9 M1)
AuditEvent (append-only, historical ids)      (schema only, Phase 9 M1)
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

Findings carry `detection_type`: `automated_detection` or
`manual_verification_required` (ADR 0009).

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

## Analysis and findings (Phase 4)

See [ADR 0009](adr/0009-deterministic-analysis-and-findings.md), the
generated [rule catalog](rules.md) and the [taxonomy policy](taxonomy.md). In
short:

- `analysis/sentinel_analysis` is a standalone, dependency-free, offline rule
  engine with 14 passive rules (at most `low` severity, no CVSS).
- Finalizing a completed or cancelled scan queues an analysis run in the same
  transaction. The worker locks the run with `SKIP LOCKED`, builds
  `ScanObservations` from the stored rows, runs the engine and stores findings
  in one transaction.
- A finding's identity is its fingerprint (rule, subject, discriminator),
  which is stable across scans. `rule_version` and the immutable
  `rule_versions` table record which logic and text produced it.

## Reports (Phase 5)

See [ADR 0010](adr/0010-evidence-backed-reporting.md) and
[reports.md](reports.md). In short:

- A report covers one assessment and one completed, analysed scan (`final`
  also requires a completed assessment). Its snapshot, built from persisted,
  redacted rows via a field allowlist, is frozen and validated against a JSON
  Schema when it is requested.
- `reports/sentinel_reports` renders it offline and deterministically: canonical
  JSON, autoescaped sandboxed Jinja2 HTML checked against a tag allowlist, and
  PDF from the same HTML via WeasyPrint with a deny-all URL fetcher. Templates
  are versioned and hash-locked.
- `python -m app.worker --role reports` (compose `report-worker`, on an
  internal network with only the database) claims, renders without a database
  session, and stores hashed artifacts (≤ 25 MB) in PostgreSQL. Triggers make
  reports, artifacts and their links immutable.

## Retests and comparisons (Phase 6)

See [ADR 0011](adr/0011-retesting-and-scan-comparison.md) and
[retesting.md](retesting.md). In short:

- A retest is an assessment of the same target with immutable links to a
  completed parent and one of its analysed scans; its scope must be contained
  in the parent's. One live retest per assessment; retests chain A → B → C.
- `sentinel_analysis.coverage` says, per rule version, which subjects a scan
  provably examined; `sentinel_analysis.comparison.classify` (policy `cmp-1`)
  turns baseline and current findings into new / reopened / unchanged /
  still_open / fixed / dismissed / not_retested / not_comparable records.
  FIXED requires same-version coverage evidence; a false positive is never
  FIXED.
- Comparisons are queued by the API and computed by the scans/analysis worker
  in one transaction (SKIP LOCKED, findings share-locked, no running state).
  Composite foreign keys and triggers keep them same-target, same-scan,
  same-identity and immutable. Triage status is never changed by comparison.

## Retest reports (Phase 7)

See [ADR 0012](adr/0012-retest-reporting.md) and
[retest-reporting.md](retest-reporting.md). In short:

- A retest report covers one completed comparison (`final` also requires a
  completed retest assessment). Its snapshot (`sentinelvapt.retest-report/1`)
  copies the comparison's records, states, reasons, coverage and history
  exactly, freezes triage status twice (when compared, when reported), and
  carries deduplicated evidence entries with per-entry SHA-256, both
  authorizations with the scope change, the lineage and limitation codes.
  Caps reject rather than truncate.
- It is a separate report type: own tables (`retest_reports`,
  `retest_report_artifacts`, `retest_report_evidence`), sequence (`SV-RT-…`),
  template `sv-retest@1` with its own registry and lockfile. Phase 5 reports,
  `sv-standard@1` and its lock are unchanged and byte-identical.
- Identical requests return the existing report (partial unique index on
  comparison, kind and content digest). Composite foreign keys bind reports to
  their comparison, scans and one target, and evidence links to the scan of
  their role; triggers require a completed comparison and make reports
  immutable. The existing `reports` worker role renders them.

## Operator console (Phase 8)

See [ADR 0013](adr/0013-frontend-architecture-and-threat-model.md) and
[frontend.md](frontend.md). In short:

- **Browser and API.** The browser talks only to Next.js on 127.0.0.1:3000.
  Server components and Server Actions call the API through a typed,
  `server-only` client. The API address is never exposed (no `NEXT_PUBLIC_*`).
- **Requests.** `proxy.ts` refuses unexpected `Host` headers (421) and
  cross-origin writes (403), and sets a per-request nonce CSP without
  `unsafe-inline`. Every Server Action repeats the Host/Origin check.
- **Hostile data.** Every API value is untrusted and rendered as text, with
  bidi and control characters shown as visible markers. URLs are not links.
  Raw-HTML APIs are banned by lint.
- **Report previews.** They run only in `<iframe sandbox="">` from an
  `/artifacts/` route that keeps the API's sandboxing CSP; downloads are
  attachments.
- **Comparisons and triage.** Comparison states are shown exactly as stored;
  triage is always a separately labelled status.
- **No backend changes.** No backend, database or migration changes, and no
  authentication (names are self-asserted).

## Identity and authorization (Phase 9, in progress)

See [ADR 0014](adr/0014-authentication-and-authorization.md). Milestone M1
adds only the schema foundation; nothing uses it yet, and the API is still
unauthenticated and localhost-only (ADR 0005).

- **Three separate concepts.** Platform identity (`users`,
  `user_credentials`, `sessions`), project membership (`project_members`:
  owner / operator / viewer) and target authorization
  (`target_authorizations`, unchanged). None implies another; the global
  `admin` role grants no project access.
- **Database rules.**
  - Credentials accept only Argon2id hashes.
  - Sessions store only a SHA-256 of the token, with frozen identity and
    lifetime and final revocation.
  - A project with members keeps at least one owner (deferred trigger).
  - `audit_events` is append-only with constrained metadata.
- **Project names** are no longer unique database-wide (`uq_projects_name`
  became the plain index `ix_projects_name`). The service still refuses
  duplicates until M4.

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
| `GET` | `/api/v1/scans/{id}/findings` (filters: `severity`, `confidence`, `detection_type`, `category`, `rule_id`, `status`), `/findings/summary`, `/analysis` |
| `GET` | `/api/v1/assessments/{id}/findings/summary` |
| `GET` | `/api/v1/findings/{id}`, `/evidence`, `/history` |
| `POST` | `/api/v1/findings/{id}/triage` (body: `status`, `reason`, `triaged_by`) |
| `GET` | `/api/v1/rules` (the rule catalog this deployment evaluates) |
| `POST`, `GET` | `/api/v1/assessments/{id}/reports` (body: `scan_id`, `kind`, `formats`, `title`, `prepared_by`, …) |
| `GET` | `/api/v1/reports/{id}`, `/artifacts`, `/artifacts/{json,html,pdf}`, `/preview` |
| `GET` | `/api/v1/report-templates` |
| `POST`, `GET` | `/api/v1/assessments/{id}/retests` |
| `GET` | `/api/v1/assessments/{id}/lineage` |
| `POST`, `GET` | `/api/v1/assessments/{id}/comparisons` (body: `scan_id`; 202 new, 200 existing) |
| `GET` | `/api/v1/comparisons/{id}`, `/records` (filters: `state`, `rule_id`), `/records/{fingerprint}` |
| `POST` | `/api/v1/assessments/{id}/comparisons/{comparison_id}/reports` (202 new, 200 identical existing) |
| `GET` | `/api/v1/assessments/{id}/retest-reports` |
| `GET` | `/api/v1/retest-reports/{id}`, `/artifacts`, `/artifacts/{json,html,pdf}`, `/preview` |
| `GET` | `/api/v1/retest-report-templates` |

Errors from business rules return `{"detail", "code", "field"}` with 404
(`not_found`), 409 (`conflict`, `invalid_state_transition`,
`target_authorization_invalid`, `retest_report_not_allowed`) or 422 (`validation_error`). Interactive docs
are at `/docs` outside production.

See [`adr/`](adr/) for the reasoning behind key decisions and
[`scope-and-ethics.md`](scope-and-ethics.md) for safety boundaries.
