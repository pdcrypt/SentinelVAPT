"""Phase 9 M7 mutation harness. Each mutation edits source, runs its named
tests, and is CAUGHT only if at least one named test FAILED (a setup ERROR
does not count). Files are restored afterwards and the tree hash checked.

Migration mutations also change the downgrade so that it undoes them; before
restoring their files the harness downgrades the shared test database to M6
with the mutated migration. Usage: python m7_mutations.py [numbers...]"""

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "backend"


def _python() -> str:
    """MUTATION_PYTHON, else the backend's virtual environment, else this
    interpreter (CI installs the packages into it)."""
    if os.environ.get("MUTATION_PYTHON"):
        return os.environ["MUTATION_PYTHON"]
    for candidate in (ROOT / ".venv" / "Scripts" / "python.exe", ROOT / ".venv" / "bin" / "python"):
        if candidate.exists():
            return str(candidate)
    return sys.executable


PY = _python()
T = "tests/integration/test_m7_admin.py::"
INV = "tests/unit/test_route_inventory.py::"
U5 = "tests/unit/test_actors.py::"
MIGRATION = "alembic/versions/20261007_d2b8e6f3a5c7_user_and_membership_administration.py"
MEMBERS = "app/services/memberships.py"
USERS = "app/services/users.py"

RESET = (
    "from alembic import command\n"
    "from tests.integration.conftest import _alembic_config, _test_database_url\n"
    "command.downgrade(_alembic_config(_test_database_url()), 'c4f7a2e9d1b6')\n"
)

OWNER_TRIGGER = ("CREATE CONSTRAINT TRIGGER project_members_keep_owner AFTER INSERT OR UPDATE "
                 "OR DELETE ON project_members DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
                 "EXECUTE FUNCTION check_project_keeps_owner()")
DROP_OWNER_TRIGGER = [
    (MIGRATION, "    op.execute(KEEP_ADMIN_TRIGGER)\n",
     "    op.execute(KEEP_ADMIN_TRIGGER)\n"
     '    op.execute("DROP TRIGGER project_members_keep_owner ON project_members")\n'),
    (MIGRATION, 'def downgrade() -> None:\n',
     f'def downgrade() -> None:\n    op.execute("{OWNER_TRIGGER}")\n'),
]
DROP_ADMIN_TRIGGER = [
    (MIGRATION, "    op.execute(KEEP_ADMIN_TRIGGER)\n", ""),
    (MIGRATION, '    op.execute("DROP TRIGGER users_keep_admin ON users")\n', ""),
]
NO_LAST_OWNER_CHECK = (MEMBERS, '''    def _other_owners(self, project_id: uuid.UUID, user_id: uuid.UUID) -> int:
        return int(''', '''    def _other_owners(self, project_id: uuid.UUID, user_id: uuid.UUID) -> int:
        return 1 or int(''')

MUTATIONS: list[tuple[str, list[tuple[str, str, str]], list[str]]] = [
    ("1 remove user.admin enforcement", [
        ("app/api/v1/routers/users.py",
         "AdminDep = Annotated[AccessDecision, Depends(require_global(P.USER_ADMIN))]",
         "AdminDep = Annotated[AccessDecision, Depends(require_global(P.CATALOG_READ))]"),
     ], [T + "test_only_global_admins_administer_accounts", INV + "test_every_route_is_classified_exactly_once"]),
    ("2 remove membership.manage enforcement", [
        ("app/api/v1/routers/members.py",
         '    AccessDecision, Depends(authorize(P.MEMBERSHIP_MANAGE, R.PROJECT, "project_id"))',
         '    AccessDecision, Depends(authorize(P.PROJECT_READ, R.PROJECT, "project_id"))'),
     ], [T + "test_membership_is_owner_only_and_project_scoped"]),
    ("3 let operators manage membership", [
        ("app/core/authz.py", "        Permission.RETEST_WRITE,\n    }\n)",
         "        Permission.RETEST_WRITE,\n        Permission.MEMBERSHIP_MANAGE,\n    }\n)"),
     ], [T + "test_membership_is_owner_only_and_project_scoped"]),
    ("4 give global admins project access without membership", [
        ("app/services/access.py",
         '        if resolution.role is None:\n            self._deny(principal, permission, "not_member"',
         '        if resolution.role is None and principal.global_role == "admin":\n'
         '            resolution = type(resolution)(resolution.project_id, ProjectRole.OWNER)\n'
         '        if resolution.role is None:\n            self._deny(principal, permission, "not_member"'),
        ("app/services/access.py", "from app.repositories.authz import ProjectResolver\n",
         "from app.models.enums import ProjectRole\nfrom app.repositories.authz import ProjectResolver\n"),
     ], [T + "test_membership_is_owner_only_and_project_scoped"]),
    ("5 bypass final-owner protection (service)", [NO_LAST_OWNER_CHECK],
     [T + "test_a_project_always_keeps_an_owner"]),
    ("6 bypass final-owner protection (database)", DROP_OWNER_TRIGGER,
     [T + "test_a_project_always_keeps_an_owner"]),
    ("7 accept invalid roles", [
        ("app/schemas/administration.py", "class MemberAdd(InputModel):\n    username: str = Field(min_length=1, max_length=64)\n    role: ProjectRole\n",
         "class MemberAdd(InputModel):\n    username: str = Field(min_length=1, max_length=64)\n    role: str\n"),
        (MEMBERS, "            role=ProjectRole(role),\n",
         "            role=ProjectRole(role) if role in {r.value for r in ProjectRole} else ProjectRole.VIEWER,\n"),
     ], [T + "test_member_input_is_validated"]),
    ("8 accept disabled users as new members", [
        (MEMBERS, "        if not user.is_active:\n            raise self._refuse(\n                actor,\n                project_id,",
         "        if False:\n            raise self._refuse(\n                actor,\n                project_id,"),
     ], [T + "test_member_input_is_validated"]),
    ("9 reset a disabled user's password", [
        (USERS, "        if not user.is_active:\n            raise self._refuse(\n                actor, \"reset_password\"",
         "        if False:\n            raise self._refuse(\n                actor, \"reset_password\""),
     ], [T + "test_password_reset_replaces_the_credential_and_sessions"]),
    ("10 accept an actor field in a membership request", [
        ("app/schemas/administration.py", "class MemberAdd(InputModel):\n",
         "class MemberAdd(InputModel):\n    created_by_user_id: uuid.UUID | None = None\n"),
     ], [T + "test_member_input_is_validated", U5 + "test_no_request_schema_can_name_an_actor"]),
    ("11 trust an identity header for membership changes", [
        ("app/api/v1/routers/members.py",
         "    member, user = service.add(\n        project_id, data.username, data.role, actor=UserActor.of(access.principal)\n    )",
         "    member, user = service.add(\n        project_id, data.username, data.role, actor=UserActor.of(access.principal)\n    ) if not request.headers.get('x-user-id') else service.add(\n"
         "        project_id, data.username, data.role, actor=UserActor(uuid.UUID(request.headers['x-user-id']), 'x'))"),
        ("app/api/v1/routers/members.py",
         "def add_member(\n    project_id: uuid.UUID,",
         "def add_member(\n    request: Request,\n    project_id: uuid.UUID,"),
        ("app/api/v1/routers/members.py", "from fastapi import APIRouter, Depends, status\n",
         "from fastapi import APIRouter, Depends, Request, status\n"),
     ], [T + "test_identity_never_comes_from_the_request", U5 + "test_no_code_reads_identity_from_headers"]),
    ("12 omit the audit of a membership change", [
        (MEMBERS, "        self.session.flush()\n        self.audit.user(\n            AuditAction.MEMBERSHIP_ADDED,",
         "        self.session.flush()\n        (lambda *a, **k: None)(\n            AuditAction.MEMBERSHIP_ADDED,"),
     ], [T + "test_owners_manage_members"]),
    ("13 omit the audit of a refused membership change", [
        (MEMBERS, "        self.audit.denial(\n            AuditAction.MEMBERSHIP_CHANGE_REFUSED,",
         "        return error\n        self.audit.denial(\n            AuditAction.MEMBERSHIP_CHANGE_REFUSED,"),
     ], [T + "test_member_input_is_validated", T + "test_a_project_always_keeps_an_owner"]),
    ("14 commit an account before its audit event", [
        (USERS, "        self.session.flush()\n        self.audit.user(\n            AuditAction.USER_CREATED,",
         "        self.session.flush()\n        self.session.commit()\n        self.audit.user(\n            AuditAction.USER_CREATED,"),
     ], [T + "test_account_changes_roll_back_without_their_audit"]),
    ("15 expose the password hash", [
        ("app/schemas/administration.py", "    must_change_password: bool\n    last_login_at: datetime | None\n",
         "    must_change_password: bool\n    last_login_at: datetime | None\n    password_hash: str | None = None\n"),
        (USERS, '''        user = self.session.get(User, user_id)
        if user is None:
            raise NotFoundError("user not found")
        return user''', '''        user = self.session.get(User, user_id)
        if user is None:
            raise NotFoundError("user not found")
        user.password_hash = self.users.credential(user.id).password_hash  # type: ignore[attr-defined,union-attr]
        return user'''),
     ], [T + "test_listing_and_reading_accounts"]),
    ("16 bypass cross-project containment", [
        ("app/api/v1/routers/members.py", "            R.PROJECT_MEMBER,\n            key={\"project_id\": \"project_id\", \"user_id\": \"user_id\"},",
         "            R.PROJECT,\n            key={\"id\": \"project_id\"},"),
        (MEMBERS, "            .where(ProjectMember.project_id == project_id, ProjectMember.user_id == user_id)",
         "            .where(ProjectMember.user_id == user_id)"),
     ], [T + "test_membership_is_owner_only_and_project_scoped"]),
    ("17 weaken membership concurrency protection", [
        (MEMBERS, "    def _lock_project(self, project_id: uuid.UUID) -> None:\n",
         "    def _lock_project(self, project_id: uuid.UUID) -> None:\n        return\n"),
        *DROP_OWNER_TRIGGER,
     ], [T + "test_concurrent_demotions_keep_an_owner", T + "test_concurrent_removals_and_adds"]),
    ("18 allow removing the final owner", [
        (MEMBERS, "        if role is ProjectRole.OWNER and self._other_owners(project_id, user_id) == 0:",
         "        if False:"),
     ], [T + "test_a_project_always_keeps_an_owner"]),
    ("19 allow disabling the last active administrator", [
        (USERS, "        if user.global_role is GlobalRole.ADMIN and not self._another_active_admin(user.id):",
         "        if False:"),
        *DROP_ADMIN_TRIGGER,
     ], [T + "test_the_last_active_admin_cannot_be_disabled"]),
    ("20 drop the administrator lock and the keep-an-admin trigger", [
        (USERS, "        # Lock order: the admins lock, then the user row (then their sessions).\n"
                "        self.users.lock(ADMINS_LOCK)\n",
         "        # Lock order: the admins lock, then the user row (then their sessions).\n"),
        (USERS, "        # Lock order as in disable(): the admins lock, then the user row.\n"
                "        self.users.lock(ADMINS_LOCK)\n",
         "        # Lock order as in disable(): the admins lock, then the user row.\n"),
        *DROP_ADMIN_TRIGGER,
     ], [T + "test_last_admin_checks_serialize",
         T + "test_concurrent_disables_keep_an_active_admin"]),
    ("21 let administrators disable themselves", [
        (USERS, '''        if user_id == actor.user_id:
            raise self._refuse(
                actor,
                "disable",''', '''        if False:
            raise self._refuse(
                actor,
                "disable",'''),
     ], [T + "test_admins_cannot_disable_or_reset_themselves"]),
    ("22 keep sessions after a password reset", [
        (USERS, "        revoked = self.sessions.revoke_all(\n            user.id, SessionRevocationReason.REVOKED_BY_ADMIN, self.clock()\n        )",
         "        revoked = 0"),
     ], [T + "test_password_reset_replaces_the_credential_and_sessions"]),
    ("23 keep sessions after disabling", [
        (USERS, "        revoked = self.sessions.revoke_all(user.id, SessionRevocationReason.USER_DISABLED, now)",
         "        revoked = 0"),
     ], [T + "test_disabling_revokes_sessions_and_blocks_sign_in"]),
    ("24 let new accounts keep the administrator's password", [
        (USERS, "            must_change_password=True,  # the administrator chose this password",
         "            must_change_password=False,"),
     ], [T + "test_admin_creates_an_account_that_must_change_its_password"]),
]


def tree_hash() -> str:
    h = hashlib.sha256()
    for base in ("app", "alembic"):
        for path in sorted((ROOT / base).rglob("*.py")):
            h.update(str(path).encode())
            h.update(path.read_bytes())
    return h.hexdigest()


def clean_tree() -> bool:
    """Mutations edit tracked files in place and restore them afterwards. A
    clean tree guarantees `git checkout -- backend` can always undo a run that
    was killed before it could restore."""
    out = subprocess.run(
        ["git", "status", "--porcelain", "--", "app", "alembic", "tests"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    return out.strip() == ""


def main() -> int:
    if not clean_tree():
        print("refusing to run: backend/app, alembic or tests have uncommitted changes")
        return 2
    wanted = {int(a) for a in sys.argv[1:]}
    before = tree_hash()
    results = []
    for name, edits, tests in MUTATIONS:
        if wanted and int(name.split()[0]) not in wanted:
            continue
        originals: dict[Path, bytes] = {}
        touches_migration = any(rel == MIGRATION for rel, _, _ in edits)
        try:
            for rel, old, new in edits:
                path = ROOT / rel
                originals.setdefault(path, path.read_bytes())
                src = path.read_text(encoding="utf-8")
                assert src.count(old) == 1, (name, rel, old[:70], src.count(old))
                path.write_text(src.replace(old, new), encoding="utf-8", newline="\n")
            proc = subprocess.run(
                [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rfE", *tests],
                cwd=ROOT, capture_output=True, text=True, timeout=1800,
            )
            failed = set(re.findall(r"^FAILED (\S+?)(?:\[| - |$)", proc.stdout, re.M))
            named = sorted({t for t in tests if any(f.startswith(t) for f in failed)})
            caught = proc.returncode != 0 and bool(named)
            results.append((name, "CAUGHT" if caught else "SURVIVED", named))
            print(f"{'CAUGHT' if caught else 'SURVIVED':8}  {name}", flush=True)
            for t in named:
                print(f"            failed: {t.split('::')[1]}", flush=True)
            if not caught:
                print(proc.stdout[-3000:], flush=True)
            if touches_migration:
                reset = subprocess.run([PY, "-c", RESET], cwd=ROOT, capture_output=True, text=True)
                assert reset.returncode == 0, reset.stderr[-2000:]
        finally:
            for path, data in originals.items():
                path.write_bytes(data)
    after = tree_hash()
    print("tree restored:", before == after)
    ok = all(v == "CAUGHT" for _, v, _ in results) and before == after
    print(f"{sum(v == 'CAUGHT' for _, v, _ in results)}/{len(results)} caught")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
