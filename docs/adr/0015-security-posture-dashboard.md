# 0015: Security posture dashboard

- Status: accepted
- Date: 2026-10-06
- Builds on: [ADR 0009](0009-deterministic-analysis-and-findings.md), [ADR 0010](0010-evidence-backed-reporting.md), [ADR 0011](0011-retesting-and-scan-comparison.md), [ADR 0014](0014-authentication-and-authorization.md)

## Context

Scans, findings, triage, comparisons and reports are all persisted, but the
console showed posture only per scan or per assessment. Index pages built
overviews by walking projects, then assessments, then one request per
assessment from the Next.js server. Those lists were capped silently, so an
overview could be incomplete without saying so.

The dashboard must answer three questions: what is the current posture of the
projects I can access, what changed in the latest retest, and where should I
look next. It must answer them from persisted facts only.

## Decision

Two read-only endpoints compute posture in SQL from the existing tables. There
is no migration, no materialized table and no cache. The console only formats
what they return.

| Route | Descriptor | Returns |
|---|---|---|
| `GET /api/v1/projects/{project_id}/posture` | `project.read` on the project | One project's posture |
| `GET /api/v1/posture?limit&offset` | authenticated; filtered by membership | A summary for each project the caller is a member of |

### Definitions

1. **Latest analysed scan of a target.** The candidates are a target's scans
   with `status = completed` that also have an analysis run with
   `status = completed`. The latest is the first by `scans.finished_at DESC,
   scans.id DESC`. The database guarantees `finished_at` is set exactly when a
   scan is terminal. Queued, running, failed and cancelled scans, and scans
   whose analysis is queued or failed, never qualify. Retest scans qualify
   like any other scan of the target.
2. **Current findings of a project.** The persisted findings of the latest
   analysed scan of each of its targets, summed across targets. Severity,
   triage status and counts are read from the `findings` rows as stored.
3. **Triage counts.** `by_status` counts the stored triage status (`open`,
   `confirmed`, `accepted_risk`, `false_positive`). **Open** means exactly
   triage status `open`; nothing is reinterpreted.
4. **Active findings.** Findings whose triage status is not `false_positive`.
   This is the reports' existing definition (`sentinel_reports.derive`), reused
   unchanged. `by_severity` counts active findings, as reports do. Severities
   are always listed in the analysis order (critical, high, medium, low,
   informational), zeros included.
5. **Retest outcome.** The project's latest *completed* comparison, by
   `comparisons.finished_at DESC, comparisons.id DESC`. Its counts are a
   `GROUP BY state` over its persisted `comparison_records`. All eight cmp-1
   states (`new`, `reopened`, `unchanged`, `still_open`, `fixed`, `dismissed`,
   `not_retested`, `not_comparable`) are always listed. Nothing is recomputed
   from findings.
6. **Latest reports.** The latest *completed* scan report and retest report of
   the project, by `finished_at DESC, id DESC`. The console links to the
   existing report pages; there is no new report logic.
7. **Recent scans.** The project's 10 most recent scans in any status, by
   `created_at DESC, id DESC`. The finding count is shown only for scans whose
   analysis completed.
8. **No score.** There is no risk score, security percentage, gauge or derived
   rating. Severity is the rules' project-defined severity (ADR 0009), not
   CVSS.

### Visibility

- Project posture uses the M3/M4 resolver: a non-member, including a global
  administrator, gets 404, as does a malformed id. Unauthenticated callers get
  401.
- The cross-project overview takes the caller's identity from the session and
  selects projects through `project_members` in SQL. It accepts no project
  ids. Every subquery is restricted to those projects before aggregating, so
  nothing from other projects can be counted or named.
- Reading posture records no audit event.

### Query shape

- A fixed number of queries per request, whatever the number of projects or
  targets: `DISTINCT ON (target)` for the latest scans, `GROUP BY` for the
  counts, `DISTINCT ON (project)` for the latest comparison and reports.
- Bounded results: recent scans are `LIMIT 10`; targets per project are
  capped at 100 with an explicit `targets_truncated` flag; the overview is
  paginated like `GET /projects` (`limit` up to 100).
- Existing indexes cover the joins at lab scale. No index is added until
  query plans show a need.

### The console

- The overview page shows the cross-project summary. The project page shows
  that project's posture. The findings overview uses the summary instead of
  walking every assessment.
- The console renders counts, charts with text equivalents, links and empty
  states. It does not decide what is open, active, latest or comparable, and
  it does not filter projects. Every string from the API is rendered as inert
  text.

## Consequences

- The dashboard is exactly as strong as the persisted data. A lab that never
  changes shows `unchanged` retests: nothing is fabricated.
- "Current" means the latest analysed scan of each target. A newer scan that
  failed or was cancelled does not change the posture. The recent scans list
  shows it.
- The reports, retests and retest-reports index pages still list through
  assessments; they are lists, not posture, and stay as they are.
