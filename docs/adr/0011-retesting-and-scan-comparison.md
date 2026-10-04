# 0011: Retesting and scan comparison

- Status: accepted
- Date: 2026-10-04
- Builds on: [ADR 0003](0003-one-target-per-assessment.md), [ADR 0006](0006-append-only-target-authorizations.md), [ADR 0009](0009-deterministic-analysis-and-findings.md), [ADR 0010](0010-evidence-backed-reporting.md)
- Supersedes: ADR 0009's note that `fixed` and `retest_required` would become triage statuses

## Context

After remediation, an authorized user needs to retest a target and learn,
from deterministic persisted evidence, which findings are new, still open,
unchanged, fixed or reopened. History must stay intact: original scans,
findings, triage, evidence and reports are immutable. "Fixed" must never be
inferred from a finding simply being absent, because absence often only means
the subject was not looked at.

## Decision

### Retest relationship: an assessment with two immutable links

A retest is an ordinary assessment of the same target with two extra columns,
set once at creation and frozen by a trigger:

- `retest_of_assessment_id`: the parent assessment, which must be completed;
- `baseline_scan_id`: a completed, analysed scan of the parent.

Composite foreign keys make the parent an assessment of the **same target**,
and the baseline scan a scan of **that parent**.

**Concurrency and uniqueness.** At most one live (not cancelled) retest per
parent, enforced by a partial unique index. Creation locks the parent and then
the target (lock order: assessment → target).

**Authorization.**

- A retest is planned under the target's *current* authorization record, which
  must not be expired and must be `local_lab`.
- Its scope must be **contained in the parent assessment's scope**:
  - same environment;
  - hosts and ports are subsets;
  - every path prefix lies within a parent prefix and outside the parent's
    exclusions;
  - every parent exclusion still reachable stays excluded.
- A wider scope is refused (`scope_expanded`), so a retest can narrow scope but
  never widen it.

After creation, the normal lifecycle applies (start, scans, complete), with
every Phase 1–3 authorization and scope check unchanged.

**Chain.** Retests chain through their parents (A → B → C …). Each retest is
compared with its **immediate parent's** pinned baseline scan.

### Identity

Comparison identity is the Phase 4 fingerprint within one target. The
fingerprint covers rule id, subject type, subject key and discriminator; it is
not presentation text, and it is unchanged here. There is no fuzzy matching:
a moved endpoint is two identities. The old one becomes FIXED or NOT_RETESTED
according to coverage, and the new one is NEW.

### Coverage: proof that a subject was examined

`sentinel_analysis.coverage` holds one coverage function per rule *version*.
Rule definitions are untouched.

- A function returns the subjects for which the scan contained input that rule
  evaluates, with the evidence ids that show it.
- Coverage is conservative:
  - a response whose relevant header value was redacted is not counted as
    examined;
  - certificate trust is never covered when the scan accepted untrusted TLS;
  - body rules need a captured excerpt;
  - the directory-listing rule needs an HTML 200 response.
- A property test checks that every subject a rule matches lies within that
  rule's coverage.
- A rule version without a coverage function has no coverage.

### Comparison policy cmp-1

`sentinel_analysis.comparison.classify` is a pure function over plain values.
For every fingerprint present in either scan:

| State | Condition |
|---|---|
| NEW | Current finding, no baseline finding, and the latest chain record is not FIXED. Reason: `first_observed` or `previously_*`. |
| REOPENED | Current finding, no baseline finding, and the most recent record for this identity in the retest chain was FIXED. |
| UNCHANGED | Both present, no meaningful difference. |
| STILL_OPEN | Both present with a meaningful difference: rule version, severity, confidence, detection type, or non-counter details. Integer counters vary with crawl size and are ignored. |
| DISMISSED | Baseline finding triaged `false_positive` and absent now. Never FIXED. Records whether the subject was examined. |
| NOT_COMPARABLE | Baseline finding absent now, and the current run did not evaluate the rule, the rule errored, it evaluated another version, or no coverage exists for that version. |
| NOT_RETESTED | Baseline finding absent now, and the subject is outside the retest scope, or was not covered (with `partial_scan`, `tls_trust_not_evaluated` and `observations_truncated` noted), or was covered without any stored response to cite. |
| FIXED | Baseline finding (not a false positive) absent now; the same rule version evaluated without error; and coverage proves the subject was examined, with at least one current-scan evidence record. Up to 25 of those are stored. |

**Evaluated rule versions.** These come from the new
`analysis_runs.rule_versions` column. For runs recorded before Phase 6 they
come from the ruleset digest when it equals the deployment's ruleset (equal
digests mean identical rule versions); otherwise they are unknown, which makes
every absence NOT_COMPARABLE.

**Triage stays separate.** Comparison state lives only in comparison records.
`FindingStatus` is unchanged; `fixed` and `retest_required` are *not* triage
statuses. Each record captures both findings' triage status at comparison
time. Nothing is carried forward automatically.

### Storage

- **`comparisons`:** one per (current scan, policy version), unique, which is
  the idempotency key. Composite foreign keys enforce:
  - **same target:** one `target_id` shared by both scan keys;
  - **the retest relationship:** (current assessment, baseline assessment,
    baseline scan) must match the retest's own links;
  - **runs of their scans:** each analysis run belongs to its scan;
  - **the chain link:** the previous comparison's current scan is this
    comparison's baseline scan.
- **`comparison_records`:** composite foreign keys to `findings(id, scan_id,
  fingerprint)` make cross-scan and cross-identity references impossible.
  CHECKs tie each state to which findings are present, keep a false positive
  from ever being FIXED, and keep reasons to an allowlist.
- **`comparison_coverage_evidence`:** the foreign key to `evidence(id,
  scan_id)` is pinned to the current scan. It is allowed only on FIXED or
  DISMISSED records, at most 25 per record.
- **Triggers:**
  - comparison inputs never change;
  - status goes `queued → completed | failed` only;
  - completed and failed comparisons never change;
  - records and evidence links are insert-only, and only while the comparison
    is queued;
  - nothing is deleted.

### Execution

`POST /assessments/{id}/comparisons` validates and queues the comparison:

- the assessment is a retest;
- the scan is completed and analysed;
- if the parent is itself a retest, the parent's comparison of this retest's
  baseline scan must exist and be completed.

The request returns 202 for a new comparison and 200 if one already exists.

The **scans/analysis worker role** computes it with the analysis-run pattern:

1. claim with `SKIP LOCKED`;
2. share-lock both runs' findings, so a triage in flight makes it wait;
3. rebuild observations from persisted rows only;
4. compute coverage, then classify;
5. insert records and coverage evidence and complete the comparison, all in
   one transaction.

There is no running state. A crash rolls back, leaving the comparison queued.
A handled error fails it with a code only, and there are no retries. No network
access is involved, and the scanner is not touched.

## Consequences

- **History is untouched.** Findings, triage history, Phase 5 reports and their
  artifacts are never changed.
- **Retest reports are deferred to Phase 7.** Retest-specific reports
  (comparison sections, a report schema v2, a retest template) are not part of
  Phase 6. Phase 5 reports and templates are unchanged.
- **Conservative coverage** produces NOT_RETESTED and NOT_COMPARABLE where a
  less careful policy would claim FIXED. A FIXED result is therefore always
  backed by stored evidence.
- **Changing a rule's version** requires writing its coverage function for the
  new version. Until then, its absences are NOT_COMPARABLE.
- **Moved endpoints and path-normalization differences** appear as separate
  identities.
- **Not in Phase 6:** comparisons outside retest chains, cumulative views
  against the original baseline, and triage carry-forward.
