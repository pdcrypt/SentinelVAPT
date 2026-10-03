# 0007: Scanner network boundary and scan grants

- Status: accepted
- Date: 2026-10-04

## Context

Phase 2 gives the scanner network access for the first time. The scanner must
never operate without an authorized target and an active assessment, must
enforce scope on every request, and must stay independent of the backend and
its database (ADR 0001).

## Decision

**Scan grant.** The backend passes an explicit `ScanGrant`: target, assessment
and authorization ids, authorization version, assessment status, validity
window and a frozen scope snapshot. `validate_grant()` refuses to start (before
any network I/O) unless the assessment is `in_progress`, the window is active,
the environment is `local_lab` and the scope passes the scanner's own
re-validation. The window is re-checked before every request. The backend is
responsible for building the grant from the database under the existing
assessment/target locks (Phase 3). Forging a grant requires code execution in
the worker, which is outside this boundary.

**Single network choke point.** `sentinel_scanner/transport.py` is the only
module allowed to import `socket`, `ssl` or `http.client` (plus `resolver.py`
for DNS); a test enforces this. Every request, including every redirect hop:
method allowlist (GET/HEAD/OPTIONS, no bodies) → grant/cancellation/time guard
→ request budget → URL scope check on the canonical path → DNS resolution with
*every* answer checked → rate limit → connect to the checked IP (no second
resolution: no DNS rebinding) → bounded read with a byte cap and a wall-clock
deadline enforced by a watchdog that shuts the socket down.

**Standard library HTTP.** Built on `http.client` rather than httpx/requests:
no proxy environment variables, no automatic redirects, no cookie jar, IP
pinning with the original hostname for Host and TLS SNI, and no runtime
dependencies.

**Lab only.** Phase 2 refuses `authorized_external` grants; every resolved
address must be loopback or private. 6to4, Teredo and NAT64 addresses are never
treated as lab addresses, and IPv4 addresses embedded in IPv6 are held to the
IPv4 rules.

**Scope logic duplication (temporary).** The backend validates scope when it is
configured (`backend/app/services/scope.py`); the scanner enforces it at
request time (`sentinel_scanner/scope.py`) and deliberately does not trust the
caller. Their host rules are kept identical by tests on both sides. When the
backend starts depending on the scanner in Phase 3 (the allowed direction), the
backend's validation will reuse the scanner's primitives so the shared logic
lives in one place.

## Consequences

- Scope cannot be bypassed by any crawler logic: the crawler has no way to
  open a connection except through the checked transport.
- Results are returned already redacted, so later persistence and reporting
  cannot leak secrets captured during discovery.
- TLS verification is on by default. Lab targets with self-signed certificates
  need an explicit `DiscoveryConfig(verify_tls=False)`, which gives up
  protection against impersonation of the target (results integrity), not
  scope enforcement; see [checks/discovery.md](../checks/discovery.md).
- `authorized_external` targets can be created but not scanned until a later
  phase deliberately enables them.
