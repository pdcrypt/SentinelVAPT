# 0002: Run scans in a worker using a PostgreSQL job queue

- Status: accepted
- Date: 2026-10-04

## Context

Scans take seconds to minutes and must not run inside API request handlers.
Celery + Redis is the common answer but adds two moving parts.

## Decision

A separate worker process (`python -m app.worker`, added in Phase 3) claims
`queued` rows from the `scans` table with `SELECT … FOR UPDATE SKIP LOCKED`,
runs the scanner and writes results.

## Consequences

- No extra infrastructure; scan state and the queue are the same table.
- Adequate for a single-user lab platform. If throughput ever matters, the
  worker interface can be moved onto a real broker without changing the
  scanner.
