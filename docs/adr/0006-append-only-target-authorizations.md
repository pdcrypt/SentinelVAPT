# 0006: Append-only target authorization records

- Status: accepted
- Date: 2026-10-04

## Context

The first Phase 1 design stored a target's scope and authorization as columns
on `targets`, so every re-acknowledgment overwrote the previous one. For a
security-testing platform that loses the most important audit question: who
authorized which scope, when, and under which authorization was a given
assessment run?

## Decision

- Scope and authorization live in `target_authorizations`, one row per
  acknowledgment, numbered per target (`version`). Rows are never updated.
- `targets.current_authorization_id` points at the record in force. Creating a
  target inserts version 1; any scope change or re-authorization inserts the
  next version and moves the pointer. Renaming does not.
- `assessments.authorization_id` records the record an assessment was planned
  under. Starting an assessment requires that record to still be current and
  active.
- The database enforces it: composite foreign keys tie both pointers to records
  of the same target, and a trigger rejects UPDATEs and any DELETE except the
  cascade from deleting a whole target. Targets with assessments cannot be
  deleted, so history behind any assessment is always retained.

## Consequences

- Complete, tamper-resistant history at the database level; Phase 3 scans and
  Phase 5 reports can cite the exact record in force.
- `targets` and `target_authorizations` reference each other; the target-side
  foreign key is `DEFERRABLE INITIALLY DEFERRED` so both rows are inserted in
  one transaction and checked at commit.
- An assessment planned before a re-authorization cannot be started; a new one
  must be planned. This is deliberate: the scope may have changed.
- Deleting a target that never had an assessment removes its records with it.
