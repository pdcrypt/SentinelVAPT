"""platform administration hardening (Phase 9 M10)

Revision ID: e5c9a7b1d3f2
Revises: d2b8e6f3a5c7
Create Date: 2026-10-08

- The audit vocabulary gains `user.enabled` and `user.global_role_changed`
  (extended, never changed; the insert is idempotent).
- guard_admin_promotion(): a disabled account can never become a global
  administrator. A row trigger refuses an update that makes a user an
  administrator while the account is inactive. The last-administrator rule
  stays M7's deferred trigger (users_keep_admin), which already covers both
  disabling and demoting; nothing here competes with it.

No existing row is read or written. Downgrade drops the trigger and removes
the M10 actions no event uses (recorded history keeps its actions).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e5c9a7b1d3f2"
down_revision: str | None = "d2b8e6f3a5c7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# The M10 vocabulary (app/core/audit.py; a unit test keeps them equal).
ACTIONS = [
    ("user.enabled", "A disabled account was enabled again (its old sessions stay revoked)."),
    ("user.global_role_changed", "An account's global role changed (its sessions revoked)."),
]

PROMOTION_GUARD = """
CREATE FUNCTION guard_admin_promotion() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'a disabled account cannot become an administrator'
        USING ERRCODE = 'restrict_violation';
END;
$$
"""

PROMOTION_TRIGGER = """
CREATE TRIGGER users_no_disabled_admin_promotion
BEFORE UPDATE OF global_role, is_active ON users
FOR EACH ROW
WHEN (NEW.global_role = 'admin' AND NOT NEW.is_active AND OLD.global_role <> 'admin')
EXECUTE FUNCTION guard_admin_promotion()
"""


def upgrade() -> None:
    insert = sa.text(
        "INSERT INTO audit_actions (action, description) VALUES (:action, :description) "
        "ON CONFLICT (action) DO NOTHING"
    )
    for action, description in ACTIONS:
        op.get_bind().execute(insert, {"action": action, "description": description})
    op.execute(PROMOTION_GUARD)
    op.execute(PROMOTION_TRIGGER)


def downgrade() -> None:
    op.execute("DROP TRIGGER users_no_disabled_admin_promotion ON users")
    op.execute("DROP FUNCTION guard_admin_promotion()")
    # The vocabulary is insert-only; only a downgrade removes entries, and
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
