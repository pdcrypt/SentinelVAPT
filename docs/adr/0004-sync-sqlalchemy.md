# 0004: Synchronous SQLAlchemy

- Status: accepted
- Date: 2026-10-04

## Context

FastAPI supports async database access, but async SQLAlchemy adds complexity
(lazy-loading pitfalls, async test fixtures) with little benefit at this scale.

## Decision

Use SQLAlchemy 2.0 with synchronous sessions and `psycopg` 3. FastAPI runs sync
endpoints in a thread pool.

## Consequences

- Simpler code and tests; the worker shares the same repositories.
- Switching to async later is a contained change in `app/db` and repositories.
