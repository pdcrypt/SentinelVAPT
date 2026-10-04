# 0005: Bind to localhost until platform authentication exists

- Status: accepted
- Date: 2026-10-04

## Context

Platform login (users, sessions) is planned for the hardening phase. Until
then, anyone who can reach the API could start scans.

## Decision

`docker-compose.yml` publishes every port on `127.0.0.1` only. Tables include
`created_by`-style columns from Phase 1 so adding authentication later does not
require reshaping data.

## Consequences

- The platform is not usable from other machines until authentication lands.
- Do not change port bindings to `0.0.0.0` before then.
