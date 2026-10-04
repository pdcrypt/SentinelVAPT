# Scope and ethics

SentinelVAPT is an **authorized** assessment platform. It exists for local
security labs and for targets whose owner has explicitly authorized testing.

## Current state (Phase 1)

The project does not scan anything yet. No scanner, checks or scan endpoints
exist. What is in place today:

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
  loopback/private addresses and lab hostnames. This is an offline, name-level
  check only; what a hostname resolves to is not verified until the scanner
  exists. Encoded path segments (such as `%2e%2e`) are not yet normalized.
- **Assessments respect the authorization window.** An assessment records the
  authorization it was planned under. It cannot start unless that authorization
  is still the target's current one and is active, and cannot be created once
  the current authorization has expired.
- **Localhost-only services.** Docker Compose publishes every port on
  `127.0.0.1` only, because the platform has no user authentication yet
  ([ADR 0005](adr/0005-localhost-only-until-auth.md)).
- **No hard-coded secrets.** Configuration comes from environment variables;
  the backend refuses to start without required values and masks the database
  URL in its representation.
- **Scanner isolation.** `scanner/` cannot import backend, web framework or
  database code; a test fails if it does
  ([ADR 0001](adr/0001-monorepo-with-standalone-scanner.md)).
- **Non-root containers** for the backend and frontend.

## Planned safety controls

These are design commitments. Each one is marked with the phase that will
implement it and must ship with tests before scanning is usable.

1. **No scan without authorization** (Phase 3). The authorization record exists
   (above); the scan endpoint will re-check it and refuse to start a scan
   outside the window.
2. **Scope enforced at request time** (Phase 2). The scope allowlist is
   validated today; the scanner will additionally check every request,
   redirect hop and resolved IP address against it.
3. **Non-destructive by construction** (Phase 2). The scanner's HTTP client
   will only allow `GET`, `HEAD` and `OPTIONS`, send no attack payloads, and
   enforce request caps, rate limits and timeouts.
4. **Evidence redaction** (Phase 3). Credentials, cookies and token-like values
   will be masked before anything is stored.
5. **Audit logging** (Phase 3). Each scan will record who started it, the exact
   scope used and every check that ran.

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
