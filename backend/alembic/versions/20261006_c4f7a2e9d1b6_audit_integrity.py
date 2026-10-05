"""audit integrity (Phase 9 M6)

Revision ID: c4f7a2e9d1b6
Revises: b8d2f4a6c1e3
Create Date: 2026-10-06

The M1 audit_events table already is append-only (no UPDATE, DELETE or
TRUNCATE), sets its own time and refuses secret-like, nested or oversized
metadata. M6 adds, without touching any existing row:

- audit_actions: the closed vocabulary (action, description), referenced by
  audit_events.action (ON UPDATE/DELETE RESTRICT; the vocabulary itself is
  insert-only, extended by migrations);
- a session only on human events, and a named actor on system events;
- check_audit_event_actor(): a human event's user must exist and be active,
  and its session must be that user's;
- ix_audit_events_occurred_at for the global listing.

Downgrade removes these (existing events are untouched either way).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4f7a2e9d1b6"
down_revision: str | None = "b8d2f4a6c1e3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# The vocabulary at M6 (app/core/audit.py; a unit test keeps them equal).
# Migrations never import application code, so it is listed here.
ACTIONS = [
    ("auth.login", "A user signed in (a session was issued)."),
    (
        "auth.login_failed",
        "A sign-in was refused (unknown user, disabled, throttled, bad password).",
    ),
    ("auth.logout", "A user ended their session."),
    ("auth.password_changed", "A user changed their password (all their sessions were replaced)."),
    ("auth.password_change_failed", "A password change was refused."),
    ("auth.session_rejected", "A revoked session, or one of a disabled user, was presented."),
    (
        "auth.password_change_required",
        "A request was refused until the user changes their password.",
    ),
    ("user.created", "An account was created by a server-side command."),
    ("user.disabled", "An account was disabled and its sessions revoked."),
    ("platform.auth_enforced", "The authentication cutover was recorded."),
    ("authz.denied", "A user was refused a permission (project or global)."),
    ("project.created", "A project was created; its creator became its owner."),
    ("project.updated", "A project was renamed or described."),
    ("project.deleted", "A project was deleted."),
    ("project.claim", "A legacy project was given its first owner by a server-side command."),
    ("target.created", "A target was created."),
    ("target.updated", "A target was renamed or re-scoped."),
    ("target.deleted", "A target was deleted."),
    ("target_authorization.created", "A target authorization was acknowledged (a new version)."),
    ("assessment.created", "An assessment was planned."),
    ("assessment.updated", "An assessment was renamed or described."),
    ("assessment.deleted", "An assessment was deleted."),
    ("assessment.started", "An assessment started."),
    (
        "assessment.start_refused",
        "An assessment could not start: the target authorization was not usable.",
    ),
    ("assessment.completed", "An assessment was completed."),
    ("assessment.cancelled", "An assessment was cancelled."),
    ("retest.created", "A retest of a completed assessment was planned."),
    ("scan.requested", "A scan was requested."),
    ("scan.request_refused", "A scan request was refused (lifecycle or target authorization)."),
    ("scan.cancel_requested", "A user cancelled, or asked to cancel, a scan."),
    ("scan.refused", "A worker refused a queued scan: its grant failed the claim-time check."),
    ("scan.started", "A worker started a scan."),
    ("scan.completed", "A scan finished."),
    ("scan.cancelled", "A scan stopped after a cancellation."),
    ("scan.failed", "A scan failed (including a lost worker)."),
    ("analysis.completed", "A scan's analysis finished."),
    ("analysis.failed", "A scan's analysis failed."),
    ("finding.triaged", "A finding's triage status changed."),
    ("comparison.requested", "A retest comparison was requested."),
    ("comparison.completed", "A comparison was computed."),
    ("comparison.failed", "A comparison failed."),
    ("report.requested", "A report was requested (its snapshot frozen)."),
    ("report.completed", "A report's artifacts were generated."),
    ("report.failed", "A report could not be generated."),
    ("retest_report.requested", "A retest report was requested."),
    ("retest_report.completed", "A retest report's artifacts were generated."),
    ("retest_report.failed", "A retest report could not be generated."),
]

VOCABULARY_GUARD = """
CREATE FUNCTION guard_audit_action_changes() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'the audit vocabulary is extended, never changed'
        USING ERRCODE = 'restrict_violation';
END;
$$
"""

# A human event names an active user, and a session only of that user: an
# audit row cannot attribute an action to a disabled account or to someone
# else's session, whatever inserts it.
ACTOR_CHECK = """
CREATE FUNCTION check_audit_event_actor() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- (A missing or unknown user is refused by user_actor_has_user and the
    -- foreign key; this refuses a disabled one.)
    IF NEW.actor_type = 'user' AND EXISTS (
        SELECT 1 FROM users WHERE id = NEW.actor_user_id AND NOT is_active
    ) THEN
        RAISE EXCEPTION 'audit events can only name an active user'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.session_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM sessions WHERE id = NEW.session_id AND user_id = NEW.actor_user_id
    ) THEN
        RAISE EXCEPTION 'an audit event''s session must belong to its user'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$
"""


def upgrade() -> None:
    table = op.create_table(
        "audit_actions",
        sa.Column("action", sa.String(length=65), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("action", name=op.f("pk_audit_actions")),
    )
    op.bulk_insert(table, [{"action": a, "description": d} for a, d in ACTIONS])
    op.execute(VOCABULARY_GUARD)
    op.execute(
        "CREATE TRIGGER audit_actions_insert_only BEFORE UPDATE OR DELETE ON audit_actions "
        "FOR EACH ROW EXECUTE FUNCTION guard_audit_action_changes()"
    )
    op.create_foreign_key(
        op.f("fk_audit_events_action_audit_actions"),
        "audit_events",
        "audit_actions",
        ["action"],
        ["action"],
        onupdate="RESTRICT",
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        op.f("ck_audit_events_session_only_for_users"),
        "audit_events",
        "session_id IS NULL OR actor_type = 'user'",
    )
    op.create_check_constraint(
        op.f("ck_audit_events_system_actor_named"),
        "audit_events",
        "actor_type <> 'system' OR actor_label IS NOT NULL",
    )
    op.execute(ACTOR_CHECK)
    op.execute(
        "CREATE TRIGGER audit_events_actor_check BEFORE INSERT ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION check_audit_event_actor()"
    )
    op.create_index(
        "ix_audit_events_occurred_at", "audit_events", [sa.literal_column("occurred_at DESC")]
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_occurred_at", table_name="audit_events")
    op.execute("DROP TRIGGER audit_events_actor_check ON audit_events")
    op.execute("DROP FUNCTION check_audit_event_actor()")
    op.drop_constraint(op.f("ck_audit_events_system_actor_named"), "audit_events", type_="check")
    op.drop_constraint(
        op.f("ck_audit_events_session_only_for_users"), "audit_events", type_="check"
    )
    op.drop_constraint(
        op.f("fk_audit_events_action_audit_actions"), "audit_events", type_="foreignkey"
    )
    op.execute("DROP TRIGGER audit_actions_insert_only ON audit_actions")
    op.execute("DROP FUNCTION guard_audit_action_changes()")
    op.drop_table("audit_actions")
