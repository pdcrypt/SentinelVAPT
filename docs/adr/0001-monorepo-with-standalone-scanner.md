# 0001: Monorepo with a standalone scanner package

- Status: accepted
- Date: 2026-10-04

## Context

The scanner is the most safety-critical code and the part most likely to grow
(new checks). Coupling it to the API or database would make it harder to test
and easier to bypass its safety controls.

## Decision

One repository with `frontend/`, `backend/`, `scanner/` and `reports/`. The
scanner is a separate Python package with no dependency on FastAPI, SQLAlchemy
or backend code. It takes a scan request and returns results; persistence is
the caller's job. A test (`scanner/tests/test_package_boundary.py`) fails if
forbidden imports appear.

## Consequences

- Checks can be unit-tested against a local HTTP fixture with no database.
- The scanner can be run from a CLI against a lab target.
- The worker needs a small mapping layer between scanner dataclasses and ORM
  models.
