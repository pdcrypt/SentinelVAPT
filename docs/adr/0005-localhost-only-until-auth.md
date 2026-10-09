# 0005: Bind every published port to localhost

- Status: accepted; amended 2026-10-09 (title and consequences, see below)
- Date: 2026-10-04

## Context

Platform login (users, sessions) is planned for the hardening phase. Until
then, anyone who can reach the API could start scans.

## Decision

`docker-compose.yml` publishes every port on `127.0.0.1` only. Tables include
`created_by`-style columns from Phase 1 so adding authentication later does not
require reshaping data.

## Consequences

- The platform is not usable from other machines.
- Do not change port bindings to `0.0.0.0`.

## Amendment (2026-10-09)

This decision was first worded as "until platform authentication exists".
Phase 9 has since added authentication and authorization (ADR 0014), and that
does not lift this decision: ADR 0014 lists network exposure beyond
localhost, SaaS and cloud deployment as non-goals. Localhost-only binding
remains the policy, in addition to authentication. Exposing the platform to a
network would need its own decision record (deployment, TLS, trusted proxies,
shared sessions).
