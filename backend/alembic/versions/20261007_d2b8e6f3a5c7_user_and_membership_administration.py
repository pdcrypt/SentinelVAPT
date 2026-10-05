"""user and membership administration (Phase 9 M7)

Revision ID: d2b8e6f3a5c7
Revises: c4f7a2e9d1b6
Create Date: 2026-10-07

- The audit vocabulary gains the M7 actions (account administration and
  project membership). The vocabulary is extended, never changed; the insert
  is idempotent.
- check_platform_keeps_admin(): the platform keeps at least one active
  administrator. A deferred constraint trigger, fired when an active
  administrator is disabled or loses the role, checks at commit time under an
  advisory lock, so two concurrent changes cannot both remove the last one
  (the same technique as M1's last-owner rule).

No existing row is read or written. Downgrade drops the trigger and removes
the M7 actions no event uses (an action already recorded stays: events keep
their foreign key and history is never rewritten).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d2b8e6f3a5c7"
down_revision: str | None = "c4f7a2e9d1b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# The M7 vocabulary (app/core/audit.py; a unit test keeps them equal).
ACTIONS = [
    (
        "user.password_reset",
        "An administrator reset an account's password (sessions revoked, change required).",
    ),
    ("user.change_refused", "An account administration request was refused."),
    ("membership.added", "A user was added to a project."),
    ("membership.role_changed", "A project member's role changed."),
    ("membership.removed", "A user was removed from a project."),
    ("membership.change_refused", "A membership change was refused (e.g. the last owner)."),
]

KEEP_ADMIN = """
CREATE FUNCTION check_platform_keeps_admin() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('platform:admins', 0));
    IF NOT EXISTS (SELECT 1 FROM users WHERE global_role = 'admin' AND is_active) THEN
        RAISE EXCEPTION 'the platform must keep at least one active administrator'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NULL;
END;
$$
"""

KEEP_ADMIN_TRIGGER = """
CREATE CONSTRAINT TRIGGER users_keep_admin
AFTER UPDATE OF is_active, global_role ON users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (OLD.global_role = 'admin' AND OLD.is_active
      AND NOT (NEW.global_role = 'admin' AND NEW.is_active))
EXECUTE FUNCTION check_platform_keeps_admin()
"""


def upgrade() -> None:
    insert = sa.text(
        "INSERT INTO audit_actions (action, description) VALUES (:action, :description) "
        "ON CONFLICT (action) DO NOTHING"
    )
    for action, description in ACTIONS:
        op.get_bind().execute(insert, {"action": action, "description": description})
    op.execute(KEEP_ADMIN)
    op.execute(KEEP_ADMIN_TRIGGER)


def downgrade() -> None:
    op.execute("DROP TRIGGER users_keep_admin ON users")
    op.execute("DROP FUNCTION check_platform_keeps_admin()")
    # The vocabulary is insert-only; only this downgrade removes entries, and
    # only those no event references.
    op.execute("ALTER TABLE audit_actions DISABLE TRIGGER audit_actions_insert_only")
    op.get_bind().execute(
        sa.text(
            "DELETE FROM audit_actions a WHERE a.action = ANY(:names) "
            "AND NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.action = a.action)"
        ),
        {"names": [action for action, _ in ACTIONS]},
    )
    op.execute("ALTER TABLE audit_actions ENABLE TRIGGER audit_actions_insert_only")
