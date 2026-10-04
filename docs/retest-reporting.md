# Retest reports

A retest report documents one completed comparison between a retest scan and
its baseline scan ([retesting](retesting.md)): what was retested, under which
authorization, and what happened to each finding. It is evidence-backed and
deterministic. Comparison states are copied exactly from the stored
comparison and are never recomputed. The design is in
[ADR 0012](adr/0012-retest-reporting.md). Scan reports (Phase 5,
[reports](reports.md)) are a separate report type and are unchanged.

## Requesting a retest report

```http
POST /api/v1/assessments/{retest_id}/comparisons/{comparison_id}/reports
{
  "title": "Retest of the shop lab",
  "prepared_by": "A. Tester",
  "kind": "draft",                     // or "final"
  "formats": ["json", "html", "pdf"],  // must include json
  "template": "sv-retest@1",           // the default
  "reviewed_by": null,
  "classification": "confidential",
  "executive_summary_note": null,
  "scope_note": null
}
```

| Response | When |
|---|---|
| **202** | A new report was queued |
| **200** | An identical report (same comparison, kind and content) already exists and has not failed; it is returned |
| 404 | The comparison does not belong to this retest assessment |
| 409 `comparison_not_completed` | The comparison is queued or failed |
| 409 `assessment_not_completed` | `final` was requested before the retest assessment was completed |
| 409 `snapshot_invalid` | The data could not be frozen consistently, or a cap was exceeded (see below) |
| 422 | Invalid body, formats without json, or an unknown template |

The report is frozen when it is requested. Later triage changes, scans or
comparisons never change it. A request made after triage has changed has
different content, so it creates a new report.

## Reading it

| Endpoint | Returns |
|---|---|
| `GET /retest-reports/{id}` | Status, inputs, digests, artifacts |
| `GET /retest-reports/{id}/artifacts/{json,html,pdf}` | The artifact, as an attachment; the `ETag` is its SHA-256 |
| `GET /retest-reports/{id}/preview` | The HTML, under a sandboxing CSP |
| `GET /assessments/{id}/retest-reports` | A retest's reports, newest first |
| `GET /retest-report-templates` | Available templates and their locked hashes |

Reports are numbered `SV-RT-000001`, `SV-RT-000002`, …, separately from scan
reports (`SV-R-…`). Numbers can skip.

## What it contains (template `sv-retest@1`)

| # | Section | Notes |
|---|---|---|
| 1 | Executive summary | Counts per comparison state |
| 2 | Retest scope and authorization | The retest's own authorization (authoritative) beside the baseline's; any narrowing is stated |
| 3 | Baseline vs retest overview | Both assessments, scans and analysis runs |
| 4 | Remediation summary | Counts and the two measures below |
| 5–12 | New, Reopened, Still open, Unchanged, Fixed, Dismissed, Not retested, Not comparable | Always present; "None." when empty |
| 13 | Evidence | Every cited evidence entry, baseline then retest |
| 14 | Rule/version differences | Rule versions that differ between the two analyses |
| 15 | Limitations and interpretation | What the report cannot show, and what to verify manually |
| 16 | Retest lineage | A → B → C, with each comparison's counts |
| 17 | Methodology | Policy, versions, template hash, digests |

For each finding the report shows:

- the persisted comparison state (e.g. `FIXED`, `NOT_RETESTED`) and its reasons;
- the baseline and retest finding views, with their evidence;
- two triage statuses, labelled separately:
  - **Triage status (when compared)**: as recorded by the comparison;
  - **Triage status (when reported)**: when this report was requested.

  Neither is a comparison state.

Some states carry extra content:

| State | Extra content |
|---|---|
| FIXED | The retest evidence showing that the subject was examined |
| REOPENED | The earlier comparison that marked it fixed |
| STILL_OPEN | What changed |

## The two measures

`baseline_active` is the number of baseline findings that were not triaged as
false positives when compared.

| Measure | Formula |
|---|---|
| Verified-fixed share | fixed / baseline_active |
| Unverified share | (not_retested + not_comparable among baseline_active) / baseline_active |

Both are SentinelVAPT-specific measures, not industry metrics. The report
always shows the numerator and the denominator, and "n/a" when
`baseline_active` is 0. Dismissed, not-retested and not-comparable findings
are never counted as fixed.

## Interpreting states

- **Fixed** means the finding is absent *and* the retest provably examined
  the subject with the same rule version.
- **Dismissed** is not a fix. The baseline finding had been triaged as a
  false positive.
- **Not retested** and **not comparable** are not remediation results. The
  issue may still exist.

## Limits

The snapshot is refused (`snapshot_invalid`) rather than silently truncated
if any of these is exceeded:

- more than 25 evidence records per finding;
- more than 25 coverage evidence records per record;
- more than 5000 evidence entries;
- more than 20000 records.

Each artifact is capped at 25 MB, as for scan reports.

## Verifying a report

- `snapshot_sha256` identifies the frozen snapshot.
- `content_sha256` identifies its content, without the id, number and request
  time. Identical requests are detected with it.
- `comparison.records_sha256` covers the copied records.
- Each evidence entry carries its own `entry_sha256`.
- Re-rendering the stored snapshot reproduces the JSON and HTML bytes, and the
  PDF bytes within the same image.
