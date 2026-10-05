"""Phase 9 M3: the permission model, role tables, resource types, the access
service (against a fake resolver) and the dependency factories' fail-closed
configuration checks. No database."""

import ast
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import app
from app.api.authz import authorize, require_global
from app.core.authz import (
    GLOBAL_PERMISSIONS,
    GLOBAL_ROLE_PERMISSIONS,
    PROJECT_PERMISSIONS,
    PROJECT_ROLE_PERMISSIONS,
    AuthorizationConfigError,
    Permission,
    ResourceType,
    global_role_grants,
    project_role_grants,
)
from app.core.errors import ForbiddenError, NotFoundError
from app.models.enums import GlobalRole, ProjectRole
from app.repositories.authz import RESOLVERS, Resolution, normalize_key
from app.services.access import AccessService
from app.services.auth import Principal

P = Permission
APP_DIR = Path(app.__file__).parent

OPERATOR = {
    P.PROJECT_READ,
    P.ASSESSMENT_WRITE,
    P.SCAN_RUN,
    P.FINDING_TRIAGE,
    P.REPORT_REQUEST,
    P.RETEST_WRITE,
}
OWNER_ONLY = {
    P.PROJECT_UPDATE,
    P.PROJECT_DELETE,
    P.TARGET_MANAGE,
    P.TARGET_AUTHORIZE,
    P.ASSESSMENT_DELETE,
    P.MEMBERSHIP_MANAGE,
    P.AUDIT_READ_PROJECT,
}


def principal(role: GlobalRole = GlobalRole.USER, *, pending: bool = False) -> Principal:
    now = datetime(2026, 10, 5, tzinfo=UTC)
    return Principal(uuid.uuid4(), "u", "U", role, pending, uuid.uuid4(), now, now, now)


class FakeAudit:
    """Records the refusals the access service reports (M6)."""

    def __init__(self) -> None:
        self.denials: list[tuple[Any, ...]] = []

    def denial(self, action: Any, actor: Any, **kw: Any) -> None:
        self.denials.append((action, actor.user_id, kw.get("metadata", {}).get("reason")))


class FakeResolver:
    """Answers with a fixed resolution and records what it was asked."""

    def __init__(self, resolution: Resolution | None) -> None:
        self.resolution = resolution
        self.calls: list[tuple[ResourceType, Mapping[str, str], uuid.UUID]] = []

    def resolve(
        self, resource: ResourceType, key: Mapping[str, str], user_id: uuid.UUID
    ) -> Resolution | None:
        self.calls.append((resource, dict(key), user_id))
        return self.resolution


def service(resolution: Resolution | None) -> AccessService:
    return AccessService(FakeResolver(resolution), FakeAudit())  # type: ignore[arg-type]


# --- permission model ----------------------------------------------------------------------


def test_permissions_are_a_closed_partition() -> None:
    assert frozenset(Permission) == GLOBAL_PERMISSIONS | PROJECT_PERMISSIONS
    assert not GLOBAL_PERMISSIONS & PROJECT_PERMISSIONS
    assert {
        P.PROJECT_CREATE,
        P.CATALOG_READ,
        P.USER_ADMIN,
        P.AUDIT_READ_GLOBAL,
    } == GLOBAL_PERMISSIONS
    assert len({p.value for p in Permission}) == len(Permission)


def test_project_role_matrix_is_exact() -> None:
    assert set(PROJECT_ROLE_PERMISSIONS) == set(ProjectRole)
    assert PROJECT_ROLE_PERMISSIONS[ProjectRole.OWNER] == PROJECT_PERMISSIONS
    assert PROJECT_ROLE_PERMISSIONS[ProjectRole.OPERATOR] == OPERATOR
    assert PROJECT_ROLE_PERMISSIONS[ProjectRole.VIEWER] == {P.PROJECT_READ}
    assert OPERATOR | OWNER_ONLY == PROJECT_PERMISSIONS
    for permission in PROJECT_PERMISSIONS:
        assert project_role_grants(ProjectRole.OWNER, permission)
        assert project_role_grants(ProjectRole.OPERATOR, permission) is (permission in OPERATOR)
        assert project_role_grants(ProjectRole.VIEWER, permission) is (permission == P.PROJECT_READ)
    # Roles are strictly nested: viewer < operator < owner.
    viewer, operator, owner = (
        PROJECT_ROLE_PERMISSIONS[r]
        for r in (ProjectRole.VIEWER, ProjectRole.OPERATOR, ProjectRole.OWNER)
    )
    assert viewer < operator < owner


def test_global_role_matrix_is_exact_and_grants_no_project_permission() -> None:
    assert set(GLOBAL_ROLE_PERMISSIONS) == set(GlobalRole)
    assert GLOBAL_ROLE_PERMISSIONS[GlobalRole.USER] == {P.PROJECT_CREATE, P.CATALOG_READ}
    assert GLOBAL_ROLE_PERMISSIONS[GlobalRole.ADMIN] == GLOBAL_PERMISSIONS
    for granted in GLOBAL_ROLE_PERMISSIONS.values():
        assert not granted & PROJECT_PERMISSIONS
    assert global_role_grants(GlobalRole.ADMIN, P.USER_ADMIN)
    assert not global_role_grants(GlobalRole.USER, P.USER_ADMIN)
    assert not global_role_grants(GlobalRole.USER, P.AUDIT_READ_GLOBAL)


@pytest.mark.parametrize("permission", ["project.read", "project.admin", None, 1])
def test_unknown_permissions_raise_instead_of_answering(permission: object) -> None:
    with pytest.raises(AuthorizationConfigError):
        project_role_grants(ProjectRole.OWNER, permission)
    with pytest.raises(AuthorizationConfigError):
        global_role_grants(GlobalRole.ADMIN, permission)


def test_wrong_kind_permissions_and_unknown_roles_raise() -> None:
    with pytest.raises(AuthorizationConfigError):
        project_role_grants(ProjectRole.OWNER, P.USER_ADMIN)
    with pytest.raises(AuthorizationConfigError):
        global_role_grants(GlobalRole.ADMIN, P.PROJECT_READ)
    for role in ("admin", "superuser", None):
        with pytest.raises(AuthorizationConfigError):
            project_role_grants(role, P.PROJECT_READ)
    with pytest.raises(AuthorizationConfigError):
        global_role_grants("root", P.CATALOG_READ)


def test_no_admin_branch_in_authorization_code() -> None:
    """Project authorization never consults the global role."""
    for relative in ("services/access.py", "repositories/authz.py", "api/authz.py"):
        tree = ast.parse((APP_DIR / relative).read_text(encoding="utf-8"))
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        assert "ADMIN" not in names, relative
    tree = ast.parse((APP_DIR / "services/access.py").read_text(encoding="utf-8"))
    project_fn = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "authorize_project"
    )
    attrs = {n.attr for n in ast.walk(project_fn) if isinstance(n, ast.Attribute)}
    assert "global_role" not in attrs


# --- resource types --------------------------------------------------------------------------


def test_every_resource_type_has_a_resolver() -> None:
    assert set(RESOLVERS) == set(ResourceType)
    for resource, spec in RESOLVERS.items():
        assert spec.uuid_keys <= set(spec.keys), resource
        assert spec.keys, resource


def test_not_found_messages_match_the_api() -> None:
    assert ResourceType.SCAN.not_found == "scan not found"
    assert ResourceType.RETEST_REPORT.not_found == "retest report not found"
    assert ResourceType.COMPARISON_RECORD.not_found == "comparison record not found"
    assert ResourceType.RETEST_ASSESSMENT.not_found == "assessment not found"


def test_normalize_key() -> None:
    good = str(uuid.uuid4())
    assert normalize_key(ResourceType.SCAN, {"id": good}) == {"id": uuid.UUID(good)}
    assert normalize_key(ResourceType.SCAN, {"id": "not-a-uuid"}) is None
    assert normalize_key(ResourceType.REPORT_ARTIFACT, {"report_id": good, "format": "pdf"}) == {
        "report_id": uuid.UUID(good),
        "format": "pdf",
    }
    for bad in ({}, {"scan_id": good}, {"id": good, "extra": "x"}):
        with pytest.raises(AuthorizationConfigError):
            normalize_key(ResourceType.SCAN, bad)
    with pytest.raises(AuthorizationConfigError):
        normalize_key("scan", {"id": good})  # type: ignore[arg-type]


# --- access service --------------------------------------------------------------------------

PROJECT = uuid.uuid4()
KEY = {"id": str(uuid.uuid4())}


def test_members_get_exactly_their_role_permissions() -> None:
    for role, granted in PROJECT_ROLE_PERMISSIONS.items():
        access = service(Resolution(PROJECT, role))
        for permission in PROJECT_PERMISSIONS:
            if permission in granted:
                decision = access.authorize_project(principal(), permission, ResourceType.SCAN, KEY)
                assert (decision.project_id, decision.role) == (PROJECT, role)
                assert decision.permission is permission
                assert decision.resource_type is ResourceType.SCAN
                assert decision.resource_key == (("id", KEY["id"]),)
            else:
                with pytest.raises(ForbiddenError):
                    access.authorize_project(principal(), permission, ResourceType.SCAN, KEY)


def test_missing_and_non_member_are_the_same_404() -> None:
    errors = []
    for resolution in (None, Resolution(PROJECT, None)):
        with pytest.raises(NotFoundError) as caught:
            service(resolution).authorize_project(
                principal(), P.PROJECT_READ, ResourceType.FINDING, KEY
            )
        errors.append((caught.value.status_code, caught.value.code, caught.value.message))
    assert errors[0] == errors[1] == (404, "not_found", "finding not found")


def test_admin_without_membership_gets_404_for_every_project_permission() -> None:
    admin = principal(GlobalRole.ADMIN)
    for permission in PROJECT_PERMISSIONS:
        with pytest.raises(NotFoundError):
            service(Resolution(PROJECT, None)).authorize_project(
                admin, permission, ResourceType.PROJECT, KEY
            )


def test_admin_membership_counts_only_as_that_membership() -> None:
    admin = principal(GlobalRole.ADMIN)
    with pytest.raises(ForbiddenError):
        service(Resolution(PROJECT, ProjectRole.VIEWER)).authorize_project(
            admin, P.SCAN_RUN, ResourceType.SCAN, KEY
        )


def test_resolver_receives_the_principal_and_the_route_key() -> None:
    fake = FakeResolver(Resolution(PROJECT, ProjectRole.OWNER))
    who = principal()
    access = AccessService(fake, FakeAudit())  # type: ignore[arg-type]
    access.authorize_project(who, P.PROJECT_READ, ResourceType.TARGET, KEY)
    assert fake.calls == [(ResourceType.TARGET, KEY, who.user_id)]


def test_access_service_refuses_misconfiguration() -> None:
    access = service(Resolution(PROJECT, ProjectRole.OWNER))
    with pytest.raises(AuthorizationConfigError):
        access.authorize_project(principal(), P.USER_ADMIN, ResourceType.SCAN, KEY)
    with pytest.raises(AuthorizationConfigError):
        access.authorize_project(principal(), "project.read", ResourceType.SCAN, KEY)  # type: ignore[arg-type]
    with pytest.raises(AuthorizationConfigError):
        access.authorize_project(principal(), P.PROJECT_READ, "scan", KEY)  # type: ignore[arg-type]
    with pytest.raises(AuthorizationConfigError):
        access.authorize_global(principal(), P.PROJECT_READ)


def test_global_permissions() -> None:
    access = service(None)
    assert access.authorize_global(principal(GlobalRole.ADMIN), P.USER_ADMIN).project_id is None
    assert access.authorize_global(principal(), P.PROJECT_CREATE).permission is P.PROJECT_CREATE
    with pytest.raises(ForbiddenError):
        access.authorize_global(principal(), P.USER_ADMIN)


# --- dependency factories --------------------------------------------------------------------


def test_factories_refuse_misconfiguration_at_declaration() -> None:
    with pytest.raises(AuthorizationConfigError):
        authorize(P.USER_ADMIN, ResourceType.SCAN, "scan_id")
    with pytest.raises(AuthorizationConfigError):
        authorize("project.read", ResourceType.SCAN, "scan_id")  # type: ignore[arg-type]
    with pytest.raises(AuthorizationConfigError):
        authorize(P.PROJECT_READ, "scan", "scan_id")  # type: ignore[arg-type]
    with pytest.raises(AuthorizationConfigError):
        authorize(P.PROJECT_READ, ResourceType.SCAN)
    with pytest.raises(AuthorizationConfigError):
        authorize(P.PROJECT_READ, ResourceType.SCAN, "scan_id", key={"id": "scan_id"})
    with pytest.raises(AuthorizationConfigError):
        authorize(P.PROJECT_READ, ResourceType.REPORT_ARTIFACT, "report_id")
    with pytest.raises(AuthorizationConfigError):
        authorize(P.PROJECT_READ, ResourceType.REPORT_ARTIFACT, key={"report_id": "report_id"})
    with pytest.raises(AuthorizationConfigError):
        require_global(P.PROJECT_READ)
    authorize(
        P.PROJECT_READ,
        ResourceType.REPORT_ARTIFACT,
        key={"report_id": "report_id", "format": "fmt"},
    )
    require_global(P.USER_ADMIN)
