# Retesting

How to retest a target and compare the results with an earlier assessment.
The design and its reasoning are in
[ADR 0011](adr/0011-retesting-and-scan-comparison.md).

> Retest-specific **reports** (comparison sections in PDF/HTML/JSON reports)
> are deferred to Phase 7. In Phase 6, comparison results are available
> through the API. Phase 5 reports are unchanged.

## 1. Create a retest

```http
POST /api/v1/assessments/{completed_assessment_id}/retests
{ "name": "Retest after fixes", "baseline_scan_id": "…" }   // baseline_scan_id optional
```

Requirements:

- the parent assessment is **completed**;
- the baseline scan is a completed scan of the parent with a completed
  analysis (default: the most recently finished one);
- the target's current authorization is not expired and is `local_lab`;
- its scope is **contained in the parent assessment's scope**. You can narrow
  the scope, for example by excluding more paths, but you cannot widen it;
- there is no other retest of the same assessment that isn't cancelled.

Refusals return `409 retest_not_allowed`, with one of these `reason` values:

- `parent_not_completed`;
- `baseline_not_completed`;
- `baseline_not_analysed`;
- `retest_exists`;
- `authorization_expired`;
- `authorization_not_local_lab`;
- `scope_expanded`.

The retest is an ordinary assessment from then on:

1. `POST /assessments/{id}/start`;
2. `POST /assessments/{id}/scans`, after which the worker scans and analyses;
3. `POST /assessments/{id}/complete`.

## 2. Compare

```http
POST /api/v1/assessments/{retest_id}/comparisons
{ "scan_id": "…" }        // a completed, analysed scan of the retest
```

The response is **202** for a new comparison and **200** if one already exists
for that scan. The worker computes it offline from persisted findings and
evidence. To read the results:

| Endpoint | Returns |
|---|---|
| `GET /comparisons/{id}` | Status, inputs, policy (`cmp-1`), counts by state |
| `GET /comparisons/{id}/records?state=&rule_id=` | One record per finding identity |
| `GET /comparisons/{id}/records/{fingerprint}` | One record |
| `GET /assessments/{id}/comparisons` | The retest's comparisons |
| `GET /assessments/{id}/retests` | An assessment's retests |
| `GET /assessments/{id}/lineage` | The chain from the original assessment |

A retest of a retest (A → B → C) needs B's comparison to be completed before
C can be compared; REOPENED depends on it.

## 3. Reading the states

| State | Meaning |
|---|---|
| `new` | Found now, not in the baseline scan |
| `reopened` | Found now, after an earlier comparison in the chain marked it fixed |
| `unchanged` | Found in both, no meaningful difference |
| `still_open` | Found in both; `reasons` says what changed |
| `fixed` | Not found now, *and* the scan provably examined the subject with the same rule version; `coverage_evidence_ids` shows the evidence |
| `dismissed` | Was marked false positive and is not found now (never "fixed") |
| `not_retested` | Not found now, but the subject was out of scope or not examined |
| `not_comparable` | Not found now, but the rule did not run, failed, or ran in another version |

Each record also shows the triage status of both findings at comparison
time. Comparison never changes a finding's triage status or its history.
