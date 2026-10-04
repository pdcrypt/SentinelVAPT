# 0003: One target per assessment

- Status: accepted
- Date: 2026-10-04

## Context

An assessment could cover many targets, but that complicates authorization
checks, retest diffs and reports.

## Decision

`Assessment.target_id` is a single foreign key. A project can have many
assessments to cover many targets.

## Consequences

- Authorization and scope for an assessment are unambiguous.
- If multi-target assessments are needed later, replace the FK with an
  `assessment_targets` join table via a migration.
