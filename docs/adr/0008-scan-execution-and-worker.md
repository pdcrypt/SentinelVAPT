# 0008: Scan execution, worker and result persistence

- Status: accepted
- Date: 2026-10-04
- Refines: [ADR 0002](0002-postgres-job-queue-worker.md)

## Context

Phase 3 connects the scanner (ADR 0007) to the assessment lifecycle. A scan
must only ever run for an in-progress assessment under its current, active,
`local_lab` authorization; the scanner must never see the database; and no
transaction may stay open while the scanner talks to the network.

## Decision

**Scans are rows in `scans`**, created by the API in `queued` state and
executed by a separate worker process (`python -m app.worker`). A composite
foreign key ties each scan to its assessment's own target and authorization
record; a partial unique index allows at most one queued/running scan per
assessment.

**State machine.** `queued → running → completed | cancelled | failed`;
`queued → cancelled` (cancel before claim) or `→ failed` (refused at claim).
Terminal states are final. `completed` means the scanner ended on its own,
including when it hit a limit or the authorization expired (`stop_reason`
records why). `cancelled` only when the scanner actually stopped because of a
cancellation; a cancel request that arrives after the scanner finished leaves
the scan `completed` with `cancel_requested_at` recorded. **No automatic
retries.**

**Global lock order: assessment → target → scan.** Every multi-lock path
follows it: scan creation and worker claim lock assessment → target (→ scan);
assessment cancel locks assessment → its active scans; scan cancel, heartbeat,
finalize and reaper lock only the scan.

**Worker, per scan:**

1. *Claim* (one short transaction). Pick the oldest queued scan without a
   lock, then lock assessment → target → scan (`SKIP LOCKED`). Re-check every
   rule and **build the `ScanGrant` from those locked rows**, then run the
   scanner's own `validate_grant()` on it. Record `grant_snapshot` (an audit
   record of what the scanner was given; it is never read back as
   authorization state), mark the scan `running`, commit. A refused claim marks
   the scan `failed` with the rule that refused it.
2. *Run* (no transaction, no session). The scanner gets only the grant, a
   `DiscoveryConfig` and a cancellation token. A watcher thread uses its own
   short transactions to send heartbeats and cancels the scanner when a cancel
   is requested, the assessment leaves `in_progress`, or the target is
   re-authorized.
3. *Finalize* (one transaction). Lock the scan; if it is still `running` and
   owned by this worker, write every result row and the final status together.
   Otherwise (it was reaped) discard the results.

A *reaper* fails running scans whose heartbeat is older than the stale limit
(`worker_lost`), judged by the database clock.

**Configuration.** `allow_untrusted_tls` is the only per-scan option. Limits
are always the scanner's defaults; the recorded `config` is for audit and its
limits are never fed back to the scanner.

**Results** are normalized into `scan_logs`, `assets`, `endpoints`,
`endpoint_cookies` and `evidence`, all scan-scoped, written once at finalize,
in result order. Natural unique keys plus `INSERT … ON CONFLICT` make
re-running persistence for a scan a no-op. Cookie values are never stored;
evidence is stored exactly as the scanner redacted it.

**Packaging.** The backend imports the scanner (the allowed direction, ADR
0001), but the scanner is *not* declared as a pip dependency: it is always
installed from this repository (Dockerfile, CI, README), so pip can never
resolve a same-named package from a public index.

## Consequences

- A crash at any point leaves no half-written results; a lost worker's scan
  becomes `failed` and must be re-requested explicitly.
- Cancellation latency is up to one heartbeat (5 s) plus one request timeout.
- One scan per worker process at a time; scale by running more workers.
- Results are visible when a scan finishes; live progress is limited to the
  heartbeat (per-event streaming is deferred).
- Assessments with scans cannot be deleted, keeping the audit trail.
