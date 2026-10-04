# Scope and ethics

SentinelVAPT is an **authorized** assessment platform. It exists for local
security labs and for targets whose owner has explicitly authorized testing.

## Current state (Phase 0)

The project does not scan anything yet. No scanner checks, scan endpoints or
target models exist. What is in place today:

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

1. **No scan without authorization** (Phases 1 and 3). Every target will record
   who authorized testing, a reference (ticket, letter, lab name), a validity
   window and an explicit acknowledgment. The API will refuse to start a scan
   when any of these is missing or expired.
2. **Scope is an allowlist** (Phase 2). Hosts, ports and URL prefixes must be
   listed explicitly, with no wildcards. Redirects and DNS results will be
   re-checked against scope on every hop.
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
