# Scope and ethics

SentinelVAPT is an **authorized** assessment platform. It exists for local
security labs and for targets whose owner has explicitly authorized testing.

## Current state (Phase 2)

The scanner library can run a passive discovery scan, but nothing in the
platform invokes it yet: there is no scan API endpoint or worker until Phase 3.
What is in place today:

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
- **Non-root containers** for the backend and frontend.

## Planned safety controls

These are design commitments, marked with the phase that will implement them.

1. **Grants built from the database under locks** (Phase 3). The scan endpoint
   and worker will build the scanner's grant from the assessment and its
   authorization record while holding the existing locks, and refuse to start a
   scan outside the window.
2. **Audit logging and persisted evidence** (Phase 3). Each scan will record who
   started it, the exact grant used, every request and blocked request, and the
   redacted evidence.
3. **External targets** (later phase, not yet scheduled). `authorized_external`
   targets can be created but the scanner refuses to scan them.

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
