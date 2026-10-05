# Scope and ethics

SentinelVAPT is an **authorized** assessment platform. It exists for local
security labs and for targets whose owner has explicitly authorized testing.

## Current state (Phase 5)

Passive discovery scans of `local_lab` targets can be requested through the
API and are run by the worker, which then analyses the stored results offline
into findings; analysed scans can be turned into reports. What is in place
today:

- **Recorded, acknowledged authorization.** A target cannot be created without
  who authorized testing, a reference, a validity window and an explicit
  `acknowledge: true`. The acknowledgment time is set by the server. Changing a
  target's scope requires re-acknowledging its authorization.
- **Authorization history.** Every acknowledgment is kept as an append-only
  record together with the exact scope it covered. Records cannot be edited,
  and are only removed if their target is deleted before anything was assessed
  ([ADR 0006](adr/0006-append-only-target-authorizations.md)).
- **Validated scope allowlist.** Targets list explicit hosts, ports and path
  prefixes. Wildcards, CIDR ranges, link-local addresses (including cloud
  metadata endpoints), IPv6 zone IDs and numeric spellings of IP addresses
  (such as `0xa9fea9fe` for `169.254.169.254`) are rejected, and the base URL
  must fall inside the scope. `local_lab` targets are limited to
  loopback/private addresses and lab hostnames.
- **Assessments respect the authorization window.** An assessment records the
  authorization it was planned under. It cannot start unless that authorization
  is still the target's current one and is active, and cannot be created once
  the current authorization has expired.
- **No scan without a valid grant.** The scanner refuses to start, before any
  network I/O, unless it is given a grant for an `in_progress` assessment whose
  authorization window is active, for a `local_lab` target, with a scope that
  passes the scanner's own re-validation. The window is re-checked before every
  request ([ADR 0007](adr/0007-scanner-network-boundary.md)).
- **Scope enforced on every request.** Every request and every redirect hop is
  checked against the scope (canonical path, so `%2e%2e`, `//`, case and
  `;params` tricks cannot reach excluded paths), and *every* address a hostname
  resolves to must be loopback or private. The connection goes to the checked
  address, so DNS rebinding cannot redirect it. IPv4 addresses hidden inside
  IPv6 (mapped, 6to4, Teredo, NAT64) are checked too.
- **Non-destructive by construction.** Only `GET`, `HEAD` and `OPTIONS` exist;
  no request bodies, cookies or credentials are ever sent; forms are never
  submitted; links with query strings or state-changing-looking paths
  (`logout`, `delete`, ...) are not requested. Request count, rate, response
  size, per-request wall-clock time, redirects, depth and total time are
  capped, with hard caps that configuration cannot exceed
  ([docs/checks/discovery.md](checks/discovery.md)).
- **Grants built from the database under locks.** A scan can only be queued
  for an in-progress assessment whose authorization is still the target's
  current one, active and `local_lab`. The worker re-checks all of this under
  row locks when it claims the scan and builds the scanner's grant from those
  rows, never from stored or client-supplied data. A running scan is stopped
  if it is cancelled, its assessment leaves `in_progress`, or the target is
  re-authorized ([ADR 0008](adr/0008-scan-execution-and-worker.md)).
- **Audit trail.** Each scan keeps the exact grant the scanner was given, the
  worker that ran it, its timeline, every scanner event (including blocked
  requests) and the redacted evidence. Scans cannot be deleted, and an
  assessment with scans cannot be deleted.
- **Redaction before results leave the scanner.** Credentials, cookies,
  token-like headers, sensitive query values and secrets in body excerpts are
  masked; cookie values are never recorded.
- **Localhost-only services.** Docker Compose publishes every port on
  `127.0.0.1` only, because the platform has no user authentication yet
  ([ADR 0005](adr/0005-localhost-only-until-auth.md)).
- **No hard-coded secrets.** Configuration comes from environment variables;
  the backend refuses to start without required values and masks the database
  URL in its representation.
- **Scanner isolation.** `scanner/` cannot import backend, web framework or
  database code, and only its transport layer may open network connections;
  tests fail otherwise
  ([ADR 0001](adr/0001-monorepo-with-standalone-scanner.md)).
- **Analysis is offline and evidence-bound.** Findings come only from data
  the scan already stored: the rule engine cannot make requests, touch the
  database or call an AI service (tests enforce its imports). Every finding
  states what its evidence proves and what it does not, is at most `low`
  severity, and is marked `manual_verification_required` when a human must
  confirm the context ([ADR 0009](adr/0009-deterministic-analysis-and-findings.md)).
  Findings reference stored, redacted evidence rather than copying bodies, and
  rule errors are recorded by exception type only.
- **Reports are offline, evidence-bound records.** A report is rendered from
  a snapshot of stored, redacted data frozen when it is requested; rendering
  makes no network requests (the PDF engine refuses every URL, and the report
  worker can reach only the database) and imports neither the scanner nor the
  rule engine. Response bodies are never copied, apart from short redacted
  excerpts for body-content issues; target-controlled text is escaped and the
  output is checked against an HTML allowlist. Completed reports cannot be
  changed or deleted ([ADR 0010](adr/0010-evidence-backed-reporting.md)).
- **Non-root containers** for the backend and frontend.
- **Operator console is browser-safe** ([ADR 0013](adr/0013-frontend-architecture-and-threat-model.md)).
  - **Browser and API:** the browser talks only to the localhost console, never to
    the API.
  - **Request checks:** unexpected Host headers and cross-origin writes are refused.
  - **Hostile data:** everything captured from targets is shown as inert text, with
    hidden characters made visible, and report previews run in a script-less sandbox.
  - **Targets and names:** the console creates only `local_lab` targets. Every page
    requires a platform sign-in, and the API records who acted from the session. The
    authorization itself (who authorized testing) is what the operator enters: the
    platform records it but cannot verify it.

## Planned safety controls

1. **External targets** (later phase, not yet scheduled). `authorized_external`
   targets can be created but scans of them are refused.
2. **Least-privilege database role** (hardening phase). The API and worker
   currently connect as the database owner.

## Out of scope (will not be implemented)

- Active exploitation, payload injection, fuzzing for crashes
- Authentication bypass, credential capture or brute forcing
- Detection or WAF evasion
- Scanning arbitrary or unlisted public systems
- Denial-of-service or load-generation features

## Adding a new check

Every check needs a short doc in `docs/checks/` stating what requests it sends,
why they are non-destructive, and whether its findings are
`automated_detection` or `manual_verification_required`.

A new analysis rule must state what its evidence proves and does not prove,
use only taxonomy identifiers verified under [taxonomy.md](taxonomy.md), get a
lockfile entry, and appear in the regenerated [rule catalog](rules.md).
