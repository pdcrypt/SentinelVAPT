# 0009: Deterministic analysis, findings and triage

- Status: accepted
- Date: 2026-10-04
- Builds on: [ADR 0001](0001-monorepo-with-standalone-scanner.md), [ADR 0008](0008-scan-execution-and-worker.md)

## Context

Phase 3 stores what a passive discovery scan observed: redacted responses,
endpoints, cookies, assets and events. Phase 4 turns those stored observations
into explainable findings. The analysis must:

- stay offline (no new requests, no active probing);
- be deterministic and reproducible;
- be honest about what passive evidence can and cannot show;
- give each finding an identity that later retesting (Phase 6) can compare
  across scans.

## Decision

### A standalone, offline rule engine

`analysis/` holds the `sentinel_analysis` package. It has:

- no runtime dependencies;
- no network, database, web-framework or AI imports (`tests/test_package_boundary.py`).

It receives a `ScanObservations` value (plain frozen dataclasses built by the
backend from Phase 3 rows) and returns `FindingCandidate`s. Rules never see
ORM objects. They read a bounded `RuleContext`, in which:

- inputs are sorted, then cut at fixed limits, and a cut is reported as the
  `observations_truncated` coverage note;
- header names are lowercased;
- header values, excerpts and URLs are clipped;
- a redacted header value (`[REDACTED]`) counts as present but unknown, never
  as missing.

Exactly 14 rules ship in Phase 4 (see [rules.md](../rules.md)). Each rule
declares:

- what its evidence **proves** and what it **does not prove**;
- remediation;
- verified taxonomy mappings ([taxonomy.md](../taxonomy.md)).

No rule is above **low** severity. The severity scale is project-defined:
there is no CVSS in Phase 4.

Each rule also has a detection type:

- `automated_detection`: the evidence itself establishes the condition;
- `manual_verification_required`: the condition depends on context a human
  must confirm.

Deferred, and not implemented, because passive evidence cannot support them or
the scanner redacts what they would need:

- active probes;
- form-based rules;
- rules based on `Access-Control-Allow-Credentials` or `WWW-Authenticate`;
- SV-TRN-003.

### Identity, version and result are separate

- **Identity:** `fingerprint = sha256("v1|rule_id|subject_type|subject_key|discriminator")`.
  - It never includes scan id, run id, severity, confidence or rule version.
  - The subject is an origin (`scheme://host:port`, with the default port
    written out) or an endpoint (`METHOD url`).
- **Version:** `rule_version` records which logic produced a finding.
  - A refinement bumps the version.
  - A change of meaning needs a new rule id.
  - Phase 6 must treat a fingerprint that is absent under a different rule
    version as "not comparable", never as "fixed".
- **Metadata:** `rule_versions` stores each (rule_id, version)'s metadata once,
  with its hash.
  - A trigger rejects UPDATE and DELETE.
  - If the code ever presents different metadata for a stored version, the run
    fails with `rule_metadata_conflict`.
  - The package's `rule_metadata.lock.json` test catches this before it ships.
- **Ruleset:** `rs-<16 hex>`, a digest of the sorted `id@version:metadata_hash`
  values.

### Runs and the worker

A scan that finalizes as `completed` or `cancelled` queues an `analysis_runs`
row (unique per scan and ruleset version) **in the same transaction as its
results**. Failed scans are not analysed.

The worker processes runs before claiming new scans:

1. Lock a queued run with `SKIP LOCKED`.
2. Read the terminal scan's rows.
3. Run the engine.
4. Write rule versions, findings and evidence links, and complete the run, all
   in one transaction.

How errors are handled:

- **Crash:** nothing is committed and the run stays queued for any worker.
- **Error during analysis:** rolled back to a savepoint; the run becomes
  `failed` with a code only (`analysis_error`, `rule_metadata_conflict`,
  `ruleset_version_mismatch`, `scan_not_analysable`). There are no retries.
- **A rule raising or breaking its contract:** that rule is isolated, and the
  run records `{rule_id, error: <exception type name>}`. Exception text is
  never stored, because it may contain target data.

Coverage notes:

- `partial_scan`: the scan stopped before completing.
- `tls_trust_not_evaluated`: `allow_untrusted_tls` was used, so certificate
  trust was not checked and SV-TRN-002 cannot fire.
- `observations_truncated`: the inputs exceeded the context limits.

### Persistence and integrity

- `findings` is unique on (scan_id, fingerprint), and inserts are
  `ON CONFLICT DO NOTHING`. Re-persisting changes nothing and never overwrites
  triage.
- Composite foreign keys tie each finding to its scan's own assessment and
  target, and to an asset or endpoint *of the same scan*.
- `finding_evidence` references existing evidence of the same scan (at most 25
  per finding). Bodies are never copied into findings.
- Database CHECKs restrict:
  - `origin = 'rule'` (no manual findings in Phase 4);
  - the enum values;
  - a non-blank reason for `false_positive` and `accepted_risk`.
- Findings and analysis runs `RESTRICT` scan deletion. Scans were already not
  deletable through the API.

### Triage

`POST /findings/{id}/triage` sets one of `open`, `confirmed`, `false_positive`
or `accepted_risk`, with `triaged_by` and a reason where required.

- It runs under the finding's row lock, so concurrent triage serializes, and
  setting the current status again is refused with 409.
- Every change appends to `finding_status_changes`.
- `fixed` and `retest_required` belong to Phase 6.

Phase 4 adds neither re-analysis nor manual finding creation.

## Consequences

- Rules are unit-tested in isolation with in-memory observations. The
  backend's integration tests run a golden scan against a 127.0.0.1 lab site
  and assert the exact set of findings.
- SV-TRN-002 relies on the scanner reporting certificate failures as a
  `tls_error` event containing `CERTIFICATE_VERIFY_FAILED`. A test pins this
  contract against a local self-signed HTTPS server whose certificate is
  generated at runtime.
- The analysis package is installed from the repository (Dockerfile `COPY`,
  CI, README). It is never declared as an index dependency, which protects
  against dependency confusion.
- Adding or changing a rule means:
  1. updating metadata and the lockfile;
  2. regenerating `docs/rules.md`;
  3. verifying any new taxonomy identifier against its primary source.
