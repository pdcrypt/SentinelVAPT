"""trusted actor identity (Phase 9 M5)

Revision ID: b8d2f4a6c1e3
Revises: e3a7c1f9b2d4
Create Date: 2026-10-05

Server-owned actor identity for the actions that carry provenance (ADR 0014):

    target_authorizations.acknowledged_by_user_id   who acknowledged it
    assessments.created_by_user_id                  who created it (incl. retests)
    scans.requested_by_user_id                      who requested it
    findings.status_changed_by_user_id              who made the latest triage
    finding_status_changes.changed_by_user_id       who made the change
    reports.requested_by_user_id                    who requested it
    retest_reports.requested_by_user_id             who requested it

Each is a nullable foreign key to users (ON DELETE RESTRICT; users are never
deleted, only disabled). Purely additive: no existing row is read or written.
Existing rows keep NULL, because their actor text (acknowledged_by,
changed_by, prepared_by) was self-asserted and no user can be derived from it
without guessing; that text is not touched.

New rows must name their actor and can never change it: one trigger function,
enforce_actor_column(column), refuses an INSERT without the actor and any
UPDATE that changes it (the columns above except findings', which follows the
latest triage). A triage of a finding (a new status_changed_at) must name its
user. Workers never write these columns: they record themselves in claimed_by.

Downgrade drops the triggers, the function and the columns (and their values).

Written by hand; tests/integration/test_db_constraints.py verifies models and
migrations agree.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b8d2f4a6c1e3"
down_revision: str | None = "e3a7c1f9b2d4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (table, column, immutable actor of the row)
COLUMNS = [
    ("target_authorizations", "acknowledged_by_user_id", True),
    ("assessments", "created_by_user_id", True),
    ("scans", "requested_by_user_id", True),
    ("finding_status_changes", "changed_by_user_id", True),
    ("reports", "requested_by_user_id", True),
    ("retest_reports", "requested_by_user_id", True),
    ("findings", "status_changed_by_user_id", False),
]

ACTOR_FUNCTION = """
CREATE FUNCTION enforce_actor_column() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    col text := TG_ARGV[0];
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF to_jsonb(NEW) ->> col IS NULL THEN
            RAISE EXCEPTION '%.% must name the user who performed the action', TG_TABLE_NAME, col
                USING ERRCODE = 'not_null_violation';
        END IF;
    ELSIF (to_jsonb(NEW) ->> col) IS DISTINCT FROM (to_jsonb(OLD) ->> col) THEN
        RAISE EXCEPTION '%.% is immutable once recorded', TG_TABLE_NAME, col
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$
"""

FINDING_TRIAGE_FUNCTION = """
CREATE FUNCTION enforce_finding_triage_actor() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status_changed_at IS DISTINCT FROM OLD.status_changed_at
       AND NEW.status_changed_by_user_id IS NULL THEN
        RAISE EXCEPTION 'a triage must name the user who made it'
            USING ERRCODE = 'not_null_violation';
    END IF;
    RETURN NEW;
END;
$$
"""


def upgrade() -> None:
    for table, column, _ in COLUMNS:
        op.add_column(table, sa.Column(column, sa.Uuid(), nullable=True))
        op.create_foreign_key(
            op.f(f"fk_{table}_{column}_users"),
            table,
            "users",
            [column],
            ["id"],
            ondelete="RESTRICT",
        )
    op.execute(ACTOR_FUNCTION)
    op.execute(FINDING_TRIAGE_FUNCTION)
    for table, column, immutable in COLUMNS:
        if immutable:
            op.execute(
                f"CREATE TRIGGER {table}_actor BEFORE INSERT OR UPDATE ON {table} "
                f"FOR EACH ROW EXECUTE FUNCTION enforce_actor_column('{column}')"
            )
    op.execute(
        "CREATE TRIGGER findings_triage_actor BEFORE UPDATE ON findings "
        "FOR EACH ROW EXECUTE FUNCTION enforce_finding_triage_actor()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER findings_triage_actor ON findings")
    for table, _, immutable in COLUMNS:
        if immutable:
            op.execute(f"DROP TRIGGER {table}_actor ON {table}")
    op.execute("DROP FUNCTION enforce_finding_triage_actor()")
    op.execute("DROP FUNCTION enforce_actor_column()")
    for table, column, _ in reversed(COLUMNS):
        op.drop_constraint(op.f(f"fk_{table}_{column}_users"), table, type_="foreignkey")
        op.drop_column(table, column)
