# 0012: Retest reporting

- Status: accepted
- Date: 2026-10-04
- Builds on: [ADR 0010](0010-evidence-backed-reporting.md), [ADR 0011](0011-retesting-and-scan-comparison.md)

## Context

Phase 6 produces completed, immutable comparisons between a retest scan and
its baseline scan. Readers need a document they can hand over: what was
retested, under which authorization, which findings were fixed (and the
evidence that shows it), which are still open, new or reopened, and which
could not be verified at all.

The Phase 5 report pipeline is already in use, and its reports must stay
byte-identical. A retest report also differs in substance from a scan
report: it presents comparison states that must never be recomputed or
blurred together. A finding that simply did not appear is not "fixed", a
dismissed false positive is not "fixed", and triage status is not a
comparison state.

## Decision

### A separate report type alongside Phase 5

Retest reports have their own:

- tables: `retest_reports`, `retest_report_artifacts`, `retest_report_evidence`;
- number sequence, displayed `SV-RT-000001`;
- snapshot schema `sentinelvapt.retest-report/1` and JSON document
  `sentinelvapt.retest-report-document/1`;
- template `sv-retest@1`, with its own registry (`RETEST_TEMPLATES`) and
  lockfile (`retest-templates.lock.json`).

The Phase 5 report tables, snapshot schema, template `sv-standard@1`, its
lock hash, template registry and renderer behaviour are unchanged. A Phase 5
request cannot select the retest template, nor the reverse. The retest
renderer reuses Phase 5's sandboxed Jinja2 environment, HTML policy check,
PDF renderer and artifact helpers as library calls; it does not change them.

A pinned test renders the Phase 5 factory snapshot and compares the JSON and
HTML SHA-256 with values taken from the Phase 5 commit. It also checks the
`sv-standard@1` lock hash. Any Phase 5 change fails it.

### Eligibility

A report is requested for one comparison of one retest assessment:

| Condition | Result |
|---|---|
| The comparison does not belong to the assessment | 404 |
| The comparison is not completed (queued or failed) | 409 `comparison_not_completed` |
| `kind: final` and the retest assessment is not completed | 409 `assessment_not_completed` |
| Unknown template, or a template that fails its lock | 422 |
| Copied records do not match the stored summary, or the snapshot fails validation | 409 `snapshot_invalid` |

A database trigger independently refuses to insert a retest report for a
comparison that is not completed.

### Snapshot: copied, never recomputed

The snapshot is built in the request transaction from persisted rows,
through an explicit field allowlist. It contains:

- the comparison, with its policy version and per-state counts;
- each record's state, reasons, coverage evidence ids and history, **copied
  exactly** from `comparison_records`. Comparison states are never computed
  again, at request time or at render time;
- for each record, the baseline and retest finding views;
- the triage status of both findings, frozen twice and labelled separately:
  - `triage_when_compared`: the status the comparison recorded;
  - `triage_when_reported`: the status when the report was requested.

  Neither value is ever shown as, or used to derive, a comparison state;
- the evidence entries cited by findings or coverage, deduplicated by
  `(role, evidence_id)`, where role is `baseline` or `current`. Each entry
  carries its scan id and an `entry_sha256` over its canonical form;
- the metadata of the rule versions the findings cite, keyed `RULE@version`;
- both authorizations. The retest's own authorization is the authoritative
  scope; the baseline's is shown alongside. A computed `scope_change` lists
  removed hosts, ports and path prefixes and added exclusions;
- the retest lineage (A → B → C), with each step's comparison counts;
- limitation codes, plus `records_sha256` over the canonical records.

The record view, evidence entry and schema fields are allowlisted. Request
headers, internal errors, secrets and unrelated columns are never copied.
Evidence uses the same redacted, bounded representation as Phase 5.

Findings are read with `FOR SHARE`. A triage in flight therefore completes
before the snapshot reads triage status, or waits until the snapshot
transaction ends.

**Caps reject rather than truncate.** The snapshot is refused with
`snapshot_invalid` if any of these is exceeded:

- 25 evidence ids per finding view;
- 25 coverage evidence ids per record;
- 5000 evidence entries per snapshot;
- 20000 records per snapshot.

**Validation** runs on request and again before every render. Beyond the
schema it checks that:

- records are sorted and unique, and the summary and `records_sha256` match;
- evidence is sorted, unique, bound to the scan of its role, and every
  `entry_sha256` is correct;
- each state has the right findings present:
  - only a current finding: new, reopened;
  - both findings: still_open, unchanged;
  - only a baseline finding: fixed, dismissed, not_retested, not_comparable;
- a FIXED record has coverage evidence and was not a false positive;
- a DISMISSED record was a false positive;
- REOPENED has a history entry whose state is fixed;
- every cited evidence entry is present, and every present entry is cited;
- rule keys match their rules;
- the lineage ends at this retest and this comparison.

### Derived figures: two, labelled, with numerator and denominator

`baseline_active` is the number of baseline findings that were not triaged
false positive when compared. Two SentinelVAPT-specific measures (not
industry metrics) are shown, each with its formula, numerator and
denominator:

- **Verified-fixed share** = fixed / baseline_active;
- **Unverified share** = (not_retested + not_comparable among
  baseline_active) / baseline_active.

Both read "n/a" when `baseline_active` is 0. The percentages use integer
arithmetic, rounded half up to one decimal, so every format shows the same
text. No other score is computed: no CVSS, no risk score, and no
AI-generated conclusion.

### Document

`sv-retest@1` always renders these sections, in this order:

1. Executive summary
2. Retest scope and authorization
3. Baseline vs retest overview
4. Remediation summary
5. New
6. Reopened
7. Still open
8. Unchanged
9. Fixed
10. Dismissed
11. Not retested
12. Not comparable
13. Evidence
14. Rule/version differences
15. Limitations and interpretation
16. Retest lineage
17. Methodology

Every comparison-state section renders, and shows "None." when it is empty.

**Record order.** Within a section, records are ordered by:

1. severity;
2. rule;
3. subject;
4. discriminator;
5. fingerprint.

Evidence is ordered by role, URL, method and id.

**Labelling.**

- FIXED records list the retest evidence showing the subject was examined.
- DISMISSED says it is not a fix.
- NOT_RETESTED and NOT_COMPARABLE say they are not remediation results.

### Idempotency

A partial unique index on `(comparison_id, kind, content_sha256) WHERE
status <> 'failed'` and `INSERT … ON CONFLICT DO NOTHING` make identical
requests return the existing report with **200**. Concurrent identical
requests produce one report.

`content_sha256` leaves out the report id, number and request time. Changed
inputs therefore create a new report (**202**), as do a later triage change
and different notes. A failed report does not block a new request.

### Database guarantees

- **Comparison binding.** A composite foreign key binds the report to its
  comparison, using the comparison's baseline and current scan ids.
- **Scan binding.** The two scan FKs carry `(scan, assessment, target_id)`
  with one shared `target_id`, so both sides belong to the same target.
- **Evidence links.**
  - `retest_report_evidence` has one scan column per role.
  - A CHECK requires exactly one of them, matching the role.
  - Paired composite FKs bind each link to the report's scan of that role and
    to evidence of that scan.
  - Cited evidence cannot be deleted.
- **Triggers.**
  - Inserts require a completed comparison.
  - Reports cannot be deleted.
  - Status moves only queued → generating → completed | failed.
  - Content columns are frozen.
  - A report becomes completed only with exactly its requested artifacts.
  - Completed and failed reports, artifacts and evidence links are immutable.

### Worker

The existing `reports` worker role renders retest reports with the same
three-phase claim → render (with no database session) → finalize flow:

- Phase 5 reports are polled first.
- A reaper fails reports left `generating` with `worker_lost`.
- Finalize checks ownership, so output that arrives after reaping is
  discarded.
- Render errors store only an error code.

### API

| Method | Path | Result |
|---|---|---|
| `POST` | `/api/v1/assessments/{id}/comparisons/{comparison_id}/reports` | 202 new, 200 identical existing |
| `GET` | `/api/v1/assessments/{id}/retest-reports` | The retest's reports |
| `GET` | `/api/v1/retest-reports/{id}` | One report |
| `GET` | `/api/v1/retest-reports/{id}/artifacts` | Its artifacts |
| `GET` | `/api/v1/retest-reports/{id}/artifacts/{json,html,pdf}` | One artifact |
| `GET` | `/api/v1/retest-reports/{id}/preview` | HTML preview |
| `GET` | `/api/v1/retest-report-templates` | Available templates |

Downloads and the preview use the Phase 5 headers:

- `Content-Disposition: attachment`;
- sandboxing CSP;
- `nosniff`;
- the SHA-256 as the `ETag`.

Artifacts of an unfinished report return 409; unknown reports return 404.

## Consequences

- A retest report states only what the persisted comparison says, together
  with the evidence that supports it. Unverified outcomes are visible and
  never counted as fixes.
- Phase 5 reports and their template are untouched and byte-identical.
- Two report types exist, so a future UI lists them separately.
- Report numbers come from a sequence and are taken before the idempotency
  check, so an idempotent repeat leaves a gap in the numbering.
- Out of scope:
  - fuzzy identity matching;
  - triage carry-forward;
  - cumulative comparison against the original baseline;
  - arbitrary scan-to-scan comparison;
  - CVSS;
  - report signing;
  - DOCX, CSV and SARIF output;
  - re-analysis.
