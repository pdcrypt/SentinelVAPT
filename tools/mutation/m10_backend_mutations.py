"""Phase 9 M10 backend mutation harness: the M7 harness mechanics (a mutation
is CAUGHT only if a named test FAILED; files restored; tree hash checked),
with the M10 migration and a reset of the test database to M7."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m7_mutations as h  # noqa: E402

T = "tests/integration/test_m10_admin.py::"
MIG_T = "tests/integration/test_m10_migration.py::"
INV = "tests/unit/test_route_inventory.py::"
MIGRATION = "alembic/versions/20261008_e5c9a7b1d3f2_platform_administration_hardening.py"
USERS = "app/services/users.py"
USERS_API = "app/api/v1/routers/users.py"
MEMBERS_API = "app/api/v1/routers/members.py"
MEMBERS = "app/services/memberships.py"
AUTH = "app/services/auth.py"
SCHEMAS = "app/schemas/administration.py"

ROUTE_ENABLE = "def enable_user(user_id: str, service: ServiceDep, access: AdminDep) -> User:"
ROUTE_ROLE = "    user_id: str, data: GlobalRoleUpdate, service: ServiceDep, access: AdminDep\n"
ANY_USER = "Annotated[AccessDecision, Depends(require_global(P.CATALOG_READ))]"

MUTATIONS = [
    ("1 remove the administrator requirement of enabling", [
        (USERS_API, ROUTE_ENABLE, ROUTE_ENABLE.replace("access: AdminDep", f"access: {ANY_USER}")),
    ], [T + "test_only_global_administrators_enable_accounts", INV + "test_every_route_is_classified_exactly_once"]),
    ("2 let disabled accounts sign in", [
        (AUTH, "        elif not user.is_active:\n            reason = \"disabled\"\n",
         "        elif False:\n            reason = \"disabled\"\n"),
    ], [T + "test_enabling_lets_the_account_sign_in_again_and_nothing_else"]),
    ("3 resurrect revoked sessions after enabling", [
        (AUTH, '            else ("revoked" if row.revoked_at is not None else None)',
         "            else None"),
    ], [T + "test_enabling_lets_the_account_sign_in_again_and_nothing_else"]),
    ("4 let ordinary users change global roles (self-promotion)", [
        (USERS_API, ROUTE_ROLE, ROUTE_ROLE.replace("access: AdminDep", f"access: {ANY_USER}")),
    ], [T + "test_only_global_administrators_change_roles", INV + "test_every_route_is_classified_exactly_once"]),
    ("5 allow administrators to change their own role", [
        (USERS, '''        if user_id == actor.user_id:
            raise self._refuse(
                actor,
                "change_global_role",''', '''        if user_id == actor.user_id and False:
            raise self._refuse(
                actor,
                "change_global_role",'''),
    ], [T + "test_administrators_cannot_change_their_own_role"]),
    ("6 remove the last-administrator check of role changes", [
        (USERS, "            and not self._another_active_admin(user.id)\n", "            and False\n"),
    ], [T + "test_the_last_active_administrator_is_kept", T + "test_concurrent_demotions_keep_an_administrator"]),
    ("7 remove the database guard against promoting disabled accounts", [
        (MIGRATION, "    op.execute(PROMOTION_TRIGGER)\n", ""),
        (MIGRATION, '    op.execute("DROP TRIGGER users_no_disabled_admin_promotion ON users")\n', ""),
    ], [T + "test_a_disabled_account_cannot_be_promoted", MIG_T + "test_upgrade_downgrade_upgrade"]),
    ("8 trust a client-supplied user id for the own membership", [
        (MEMBERS_API, '''    project_id: uuid.UUID, service: ServiceDep, access: ProjectMemberSelf
) -> dict[str, Any]:''', '''    project_id: uuid.UUID,
    service: ServiceDep,
    access: ProjectMemberSelf,
    user_id: uuid.UUID | None = None,
) -> dict[str, Any]:'''),
        (MEMBERS_API, "    member = service.mine(project_id, access.principal.user_id)",
         "    member = service.mine(project_id, user_id or access.principal.user_id)"),
    ], [T + "test_identity_comes_from_the_session_only"]),
    ("9 let non-members read a membership", [
        (MEMBERS_API, '''ProjectMemberSelf = Annotated[
    AccessDecision, Depends(authorize(P.PROJECT_READ, R.PROJECT, "project_id"))
]''', f'''ProjectMemberSelf = {ANY_USER}'''),
        (MEMBERS_API, "from app.api.authz import authorize", "from app.api.authz import authorize, require_global"),
        (MEMBERS, '''        if member is None:  # pragma: no cover  # project.read implies membership
            raise NotFoundError("project not found")''', '''        if member is None:
            member = ProjectMember(project_id=project_id, user_id=user_id, role=ProjectRole.VIEWER)'''),
    ], [T + "test_non_members_cannot_tell_a_project_exists", INV + "test_every_route_is_classified_exactly_once"]),
    ("10 expose another member's role", [
        (MEMBERS_API, "    member = service.mine(project_id, access.principal.user_id)",
         "    member = service.list(project_id)[0][0]"),
    ], [T + "test_members_read_their_own_role_and_nothing_else"]),
    ("11 skip the enable audit event", [
        (USERS, '        self.audit.user(AuditAction.USER_ENABLED, actor, resource=("user", user.id))\n', ""),
    ], [T + "test_enabling_lets_the_account_sign_in_again_and_nothing_else"]),
    ("12 skip the global-role audit event", [
        (USERS, '''        self.audit.user(
            AuditAction.USER_GLOBAL_ROLE_CHANGED,''', '''        if False:
          self.audit.user(
            AuditAction.USER_GLOBAL_ROLE_CHANGED,'''),
    ], [T + "test_administrators_promote_and_demote_and_sessions_restart"]),
    ("13 make a global administrator a member of every project", [
        (USERS, "        user.global_role = role\n", '''        user.global_role = role
        if role is GlobalRole.ADMIN:
            from sqlalchemy import text as _t
            self.session.execute(_t(
                "INSERT INTO project_members (project_id, user_id, role) "
                "SELECT id, :u, 'viewer' FROM projects ON CONFLICT DO NOTHING"), {"u": user.id})
'''),
    ], [T + "test_global_roles_never_touch_project_membership"]),
    ("14 keep sessions across a global-role change", [
        (USERS, '''        revoked = self.sessions.revoke_all(
            user.id, SessionRevocationReason.ROLE_CHANGED, self.clock()
        )''', "        revoked = 0"),
    ], [T + "test_administrators_promote_and_demote_and_sessions_restart"]),
    ("15 reset the pending password change when enabling", [
        (USERS, "        user.disabled_at = None\n        self.session.flush()\n",
         "        user.disabled_at = None\n        user.must_change_password = True\n        self.session.flush()\n"),
    ], [T + "test_enabling_lets_the_account_sign_in_again_and_nothing_else"]),
    ("16 let the service promote disabled accounts", [
        (USERS, "        if role is GlobalRole.ADMIN and not user.is_active:", "        if False:"),
    ], [T + "test_a_disabled_account_cannot_be_promoted"]),
    ("17 accept extra fields (a body naming another account)", [
        (SCHEMAS, "class GlobalRoleUpdate(InputModel):", "class GlobalRoleUpdate(BaseModel):"),
        (SCHEMAS, "from pydantic import Field", "from pydantic import BaseModel, Field"),
    ], [T + "test_roles_are_a_strict_enum_and_the_path_names_the_account"]),
]

if __name__ == "__main__":
    h.MUTATIONS = MUTATIONS
    h.MIGRATION = MIGRATION
    h.RESET = h.RESET.replace("'c4f7a2e9d1b6'", "'d2b8e6f3a5c7'")
    assert "'d2b8e6f3a5c7'" in h.RESET
    sys.exit(h.main())
