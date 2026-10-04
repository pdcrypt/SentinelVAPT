"""core domain: projects, targets, target authorizations, assessments

Revision ID: 581c955e637f
Revises:
Create Date: 2026-10-04 11:12:53.443559

Written by hand (autogenerate does not handle the circular target <->
authorization foreign key or the trigger). Enum columns are VARCHAR(32) with
one named CHECK constraint each. tests/integration/test_db_constraints.py
verifies the models and this migration do not drift.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "581c955e637f"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _created_at() -> sa.Column[object]:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
    )


def _updated_at() -> sa.Column[object]:
    return sa.Column(
        "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
    )


# Authorization records are append-only. UPDATE is always rejected. DELETE is
# only allowed when the parent target no longer exists, i.e. as part of the
# ON DELETE CASCADE from deleting a target (which the API only permits for
# targets without assessments).
IMMUTABILITY_FUNCTION = """
CREATE FUNCTION prevent_target_authorization_changes() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'target authorization records are immutable'
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF EXISTS (SELECT 1 FROM targets WHERE id = OLD.target_id) THEN
        RAISE EXCEPTION 'target authorization records cannot be deleted while their target exists'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN OLD;
END;
$$
"""

IMMUTABILITY_TRIGGER = """
CREATE TRIGGER target_authorizations_immutable
BEFORE UPDATE OR DELETE ON target_authorizations
FOR EACH ROW EXECUTE FUNCTION prevent_target_authorization_changes()
"""


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        _created_at(),
        _updated_at(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_projects")),
        sa.UniqueConstraint("name", name=op.f("uq_projects_name")),
    )

    # The unique (project_id, name) index also serves project_id lookups, so
    # there is no separate project_id index.
    op.create_table(
        "targets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("current_authorization_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        _created_at(),
        _updated_at(),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_targets_project_id_projects"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_targets")),
        sa.UniqueConstraint("project_id", "name", name=op.f("uq_targets_project_id_name")),
    )

    op.create_table(
        "target_authorizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        # Acknowledged scope
        sa.Column("base_url", sa.String(length=2048), nullable=False),
        sa.Column("environment", sa.String(length=32), nullable=False),
        sa.Column("in_scope_hosts", postgresql.ARRAY(sa.String(length=255)), nullable=False),
        sa.Column("allowed_ports", postgresql.ARRAY(sa.Integer()), nullable=False),
        sa.Column(
            "in_scope_path_prefixes", postgresql.ARRAY(sa.String(length=2048)), nullable=False
        ),
        sa.Column(
            "excluded_paths",
            postgresql.ARRAY(sa.String(length=2048)),
            server_default="{}",
            nullable=False,
        ),
        # Authorization
        sa.Column("authorized_by", sa.String(length=200), nullable=False),
        sa.Column("reference", sa.String(length=200), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_by", sa.String(length=200), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=False),
        _created_at(),
        sa.CheckConstraint(
            "environment IN ('local_lab', 'authorized_external')",
            name=op.f("ck_target_authorizations_target_environment"),
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_target_authorizations_version_positive")),
        sa.CheckConstraint(
            "cardinality(in_scope_hosts) > 0",
            name=op.f("ck_target_authorizations_has_in_scope_hosts"),
        ),
        sa.CheckConstraint(
            "cardinality(allowed_ports) > 0",
            name=op.f("ck_target_authorizations_has_allowed_ports"),
        ),
        sa.CheckConstraint(
            "cardinality(in_scope_path_prefixes) > 0",
            name=op.f("ck_target_authorizations_has_in_scope_path_prefixes"),
        ),
        sa.CheckConstraint(
            "valid_until > valid_from", name=op.f("ck_target_authorizations_validity_window")
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name=op.f("fk_target_authorizations_target_id_targets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_target_authorizations")),
        sa.UniqueConstraint(
            "target_id", "version", name=op.f("uq_target_authorizations_target_id_version")
        ),
        sa.UniqueConstraint("id", "target_id", name=op.f("uq_target_authorizations_id_target_id")),
    )

    # Circular reference: a target's current authorization must belong to that
    # target. Deferred so a target and its first authorization can be inserted
    # in one transaction.
    op.create_foreign_key(
        "fk_targets_current_authorization",
        "targets",
        "target_authorizations",
        ["current_authorization_id", "id"],
        ["id", "target_id"],
        deferrable=True,
        initially="DEFERRED",
    )

    op.execute(IMMUTABILITY_FUNCTION)
    op.execute(IMMUTABILITY_TRIGGER)

    op.create_table(
        "assessments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), server_default="planned", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        _created_at(),
        _updated_at(),
        sa.CheckConstraint(
            "status IN ('planned', 'in_progress', 'completed', 'cancelled')",
            name=op.f("ck_assessments_assessment_status"),
        ),
        sa.CheckConstraint(
            "completed_at IS NULL OR started_at IS NOT NULL",
            name=op.f("ck_assessments_completed_requires_started"),
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name=op.f("fk_assessments_target_id_targets"),
            ondelete="RESTRICT",
        ),
        # The authorization an assessment was planned under must belong to its target.
        sa.ForeignKeyConstraint(
            ["authorization_id", "target_id"],
            ["target_authorizations.id", "target_authorizations.target_id"],
            name="fk_assessments_authorization",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assessments")),
    )
    op.create_index(op.f("ix_assessments_target_id"), "assessments", ["target_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_assessments_target_id"), table_name="assessments")
    op.drop_table("assessments")
    op.execute("DROP TRIGGER target_authorizations_immutable ON target_authorizations")
    op.execute("DROP FUNCTION prevent_target_authorization_changes()")
    op.drop_constraint("fk_targets_current_authorization", "targets", type_="foreignkey")
    op.drop_table("target_authorizations")
    op.drop_table("targets")
    op.drop_table("projects")
