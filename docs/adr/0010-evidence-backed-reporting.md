# 0010: Evidence-backed reporting

- Status: accepted
- Date: 2026-10-04
- Builds on: [ADR 0001](0001-monorepo-with-standalone-scanner.md), [ADR 0002](0002-postgres-job-queue-worker.md), [ADR 0008](0008-scan-execution-and-worker.md), [ADR 0009](0009-deterministic-analysis-and-findings.md)

## Context

Phase 4 produces findings from a scan's stored, redacted evidence. Phase 5
turns one analysed scan into a professional VAPT report in three formats:
JSON (machine-readable), HTML and PDF.

A report must be:

- **auditable:** it cites the exact authorization, scope, rule versions and
  evidence it is based on;
- **reproducible:** the same input gives the same output;
- **safe:** no secrets, and no script or markup injection from target-controlled
  data;
- **independent:** reporting must not perform scanning, must not need network
  access, and must not depend on the scanner or the analysis engine.

## Decision

### Snapshot when requested, render later

`POST /assessments/{id}/reports` builds an immutable **snapshot**: one JSON
document with everything the report shows. It is built in the same transaction
that queues the report.

- **Source.** Only persisted rows, read in that one transaction. The run's
  findings are share-locked, so a concurrent triage waits and the snapshot sees
  each finding and its history consistently.
- **Field allowlist.** The builder (`app/services/report_snapshot.py`) copies
  an explicit set of fields. It never copies:
  - raw bodies or request headers;
  - scan logs or error messages;
  - grant snapshots or authorization notes.
- **Evidence.** Each evidence record carries:
  - its redacted response headers (bounded);
  - `body_sha256`, labelled "SHA-256 of the unredacted captured response
    bytes.";
  - a bounded excerpt (≤ 1 KB, already redacted by the scanner) only for issues
    whose evidence is body text: SV-INF-002 and SV-INF-003.
- **Rule text.** Rule text and taxonomy ids come from the stored
  `rule_versions` row that produced each finding.
- **Taxonomy titles.** The backend resolves display titles for those verified
  ids from the analysis package's taxonomy and freezes them into the snapshot.
  `sentinel_reports` never imports the analysis package.
- **Authorization and scope.** These come from the scan's own authorization
  record. A later re-authorization of the target does not change a report.
- **Validation.** The snapshot is validated against the committed JSON Schema
  (`report-snapshot.schema.json`, `sentinelvapt.report/1`) and checked for
  internal consistency:
  - canonical ordering;
  - every cited evidence id present and nothing uncited;
  - no duplicate findings.

  It is validated before it is stored and again before it is rendered.

### Eligibility

| Kind | Requires |
| ---- | -------- |
| draft | completed scan + completed analysis run (assessment may be in progress) |
| final | the above + assessment `completed` |

Open findings do not block a final report. They are shown as open, and
manual-verification findings are marked "requires verification". False
positives are listed in their own section and excluded from the counts.

### Rendering: a pure function

`sentinel_reports.render_report(snapshot, formats)` is a pure function of
snapshot + template version + renderer version. It uses no clock (the request
time comes from the snapshot), no randomness, no database and no network.

- **JSON:** canonical JSON (sorted keys, compact, UTF-8) holding the snapshot,
  the derived figures and an integrity block (snapshot and content digests,
  template hash, renderer version).
- **HTML:** Jinja2 in its immutable sandbox, configured as follows:
  - autoescape always on;
  - `StrictUndefined`, so a missing value fails the render;
  - every printed value has control and bidirectional-override characters
    replaced;
  - no `|safe` filter, no scripts, no style attributes, no external resources;
  - links only to an allowlist of reference hosts (OWASP Top 10, WSTG, MITRE
    CWE); target URLs are shown as text;
  - a CSP meta tag.

  The rendered HTML is then parsed and checked against a tag and attribute
  allowlist; any violation fails the render.
- **PDF:** WeasyPrint prints the same HTML (one source; print CSS for paging),
  with these settings:
  - a URL fetcher that refuses every URL, including http, https, file and
    data, and aborts the render on the first attempt;
  - no base URL;
  - no attachments or forms;
  - local DejaVu fonts;
  - metadata dates and the PDF identifier derived from the snapshot.

  The same snapshot gives byte-identical PDFs in the same environment.

Each artifact is hashed (SHA-256) and limited to 25 MB.

### Versioned templates

A template is a directory `sentinel_reports/templates/<id>/<version>/`. It
holds all of the report's wording, so the API contains none. The hash of its
files, with line endings normalized, must match `templates.lock.json`, or the
template refuses to render. A changed template therefore needs a new version.
Each report records the template id, version and hash.

### Storage and integrity

Artifacts are stored in PostgreSQL `bytea`, in the same database as the
report. CHECK constraints enforce, for each artifact:

- `size_bytes = octet_length(content)`;
- a size of at most 25 MB;
- `sha256 = encode(sha256(content), 'hex')`.

Triggers enforce:

- **Reports.**
  - Content columns (snapshot, digests, scan, run, kind, title and so on) never
    change.
  - The status may only move `queued → generating → completed`, or
    `queued | generating → failed`.
  - Completed and failed reports never change at all.
  - Reports are never deleted.
  - A report can only complete with exactly the artifacts it requested.
- **Artifacts.** Insert-only, while their report is `generating`, and only in a
  requested format.
- **Links.** `report_findings` (with the status at report time) and
  `report_evidence` are insert-only, while the report is `queued`. Composite
  foreign keys keep them inside the report's own scan, and `RESTRICT` keeps
  cited findings and evidence from being deleted.

### Worker

Report generation uses the existing PostgreSQL queue pattern, in a separate
process role: `python -m app.worker --role reports`.

| Role | Work |
| ---- | ---- |
| `scans` | scans and their analysis runs (compose service `worker`) |
| `reports` | report generation (compose service `report-worker`) |
| `all` | both, for local development |

Generation has three phases, as for scans:

1. **Claim.** `SKIP LOCKED`; the report becomes `generating`.
2. **Render.** No database session is open.
3. **Finalize.** Artifacts are written and the report completes in one
   transaction, only if this worker still owns the report.

How failures are handled:

- **Renderer error.** Stored as a code only, never exception text.
- **Worker that stops mid-render.** The reaper fails the report as
  `worker_lost` after `WORKER_REPORT_STALE_AFTER_SECONDS` (default 600),
  judged by the database clock. Late output from that worker is discarded.
- **Retries.** None.

In Compose, `report-worker` is attached only to an internal network shared
with the database. It cannot reach lab targets, the backend or the internet.

### API

| Method and path | Behaviour |
| --------------- | --------- |
| `POST /assessments/{id}/reports` | Returns 202 with the queued report. |
| `GET /assessments/{id}/reports` | Lists the assessment's reports. |
| `GET /reports/{id}` | Metadata, hashes and artifact list. |
| `GET /reports/{id}/artifacts` | The artifact list. |
| `GET /reports/{id}/artifacts/{json,html,pdf}` | Downloads an artifact. |
| `GET /reports/{id}/preview` | The HTML artifact, inline. |
| `GET /report-templates` | The available templates. |

Response headers:

- **Downloads:** `Content-Disposition: attachment` with a server-generated
  filename, `nosniff`, `no-store`, the ETag set to the artifact's SHA-256, and
  `Content-Security-Policy: default-src 'none'; sandbox`.
- **Preview:** a sandboxing CSP with no scripts and no network.

There is no edit or delete endpoint: reports are records.

## Consequences

- One report covers one assessment and one scan. Merging findings across scans
  and comparing scans need Phase 6 identity semantics ("fixed", "still
  present", "not comparable"), so they are deferred.
- The backend image now includes Pango, HarfBuzz and DejaVu fonts. Local
  Windows development usually lacks Pango: PDF tests are skipped there and
  required in CI and in the Docker test run, the same pattern as the database
  tests. JSON and HTML render everywhere.
- The JSON Schema is the single definition of the snapshot's structure, used by
  both the backend and the renderer.
- Test cleanup deletes reports by switching triggers off for that one
  transaction (`session_replication_role = replica`, superuser only). No
  production code path can delete or alter a report.
- Reports concentrate sensitive data while the platform has no authentication.
  The localhost-only boundary (ADR 0005) still applies.
