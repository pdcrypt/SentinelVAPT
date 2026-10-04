# Cross-component tests

Per-component tests live with their code (`backend/tests`, `scanner/tests`,
`reports/tests`, `frontend/tests/e2e`). This folder is for tests that span
components:

- `e2e/`: full-stack scenarios against the running docker compose stack.
- `lab/`: deliberately misconfigured fixture targets used by scanner and
  end-to-end tests (added in Phase 2).
