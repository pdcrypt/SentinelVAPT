"""Authorization model (ADR 0014, Phase 9 M3): one closed set of permissions,
the role tables that grant them, the project-scoped resource types, and the
descriptors routes use to declare what they require.

Three boundaries stay separate:
- authentication (who the user is) comes from the session (M2);
- project authorization (what the user may do in a project) comes only from
  `project_members` and the tables below;
- target authorization (may the target be tested at all) stays in the Phase 1
  services, the worker and the scanner. SCAN_RUN never implies it.

Everything here fails closed: an unknown permission, role, resource type or
descriptor raises AuthorizationConfigError (a programming defect, answered
with a logged 500), never an allow. The global `admin` role grants no project
permission: there is no admin branch anywhere in project authorization.
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from app.models.enums import GlobalRole, ProjectRole

if TYPE_CHECKING:
    from app.services.auth import Principal


class AuthorizationConfigError(RuntimeError):
    """An authorization declaration or lookup that cannot be evaluated: an
    unknown permission/role/resource type, a missing or malformed descriptor.
    Always a defect; never converted into an allow."""


class Permission(StrEnum):
    # Project-scoped (granted by project membership only).
    PROJECT_READ = "project.read"
    PROJECT_UPDATE = "project.update"
    PROJECT_DELETE = "project.delete"
    TARGET_MANAGE = "target.manage"
    TARGET_AUTHORIZE = "target.authorize"
    ASSESSMENT_WRITE = "assessment.write"
    ASSESSMENT_DELETE = "assessment.delete"
    SCAN_RUN = "scan.run"
    FINDING_TRIAGE = "finding.triage"
    REPORT_REQUEST = "report.request"
    RETEST_WRITE = "retest.write"
    MEMBERSHIP_MANAGE = "membership.manage"
    AUDIT_READ_PROJECT = "audit.read_project"
    # Global (granted by the global role only; never imply project access).
    PROJECT_CREATE = "project.create"
    CATALOG_READ = "catalog.read"
    USER_ADMIN = "user.admin"
    AUDIT_READ_GLOBAL = "audit.read_global"


GLOBAL_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.PROJECT_CREATE,
        Permission.CATALOG_READ,
        Permission.USER_ADMIN,
        Permission.AUDIT_READ_GLOBAL,
    }
)
PROJECT_PERMISSIONS: frozenset[Permission] = frozenset(Permission) - GLOBAL_PERMISSIONS

_OPERATOR: frozenset[Permission] = frozenset(
    {
        Permission.PROJECT_READ,
        Permission.ASSESSMENT_WRITE,
        Permission.SCAN_RUN,
        Permission.FINDING_TRIAGE,
        Permission.REPORT_REQUEST,
        Permission.RETEST_WRITE,
    }
)

# The only source of project permissions.
PROJECT_ROLE_PERMISSIONS: Mapping[ProjectRole, frozenset[Permission]] = {
    ProjectRole.OWNER: PROJECT_PERMISSIONS,
    ProjectRole.OPERATOR: _OPERATOR,
    ProjectRole.VIEWER: frozenset({Permission.PROJECT_READ}),
}

# The only source of global permissions. Disjoint from project permissions.
GLOBAL_ROLE_PERMISSIONS: Mapping[GlobalRole, frozenset[Permission]] = {
    GlobalRole.USER: frozenset({Permission.PROJECT_CREATE, Permission.CATALOG_READ}),
    GlobalRole.ADMIN: GLOBAL_PERMISSIONS,
}


def project_role_grants(role: object, permission: object) -> bool:
    """Whether a project role grants a project permission. Unknown values
    raise instead of answering."""
    if not isinstance(permission, Permission) or permission not in PROJECT_PERMISSIONS:
        raise AuthorizationConfigError(f"not a project permission: {permission!r}")
    try:
        granted = PROJECT_ROLE_PERMISSIONS[ProjectRole(role)]  # type: ignore[arg-type]
    except (ValueError, KeyError):
        raise AuthorizationConfigError(f"unknown project role: {role!r}") from None
    return permission in granted


def global_role_grants(role: object, permission: object) -> bool:
    """Whether a global role grants a global permission (never a project one)."""
    if not isinstance(permission, Permission) or permission not in GLOBAL_PERMISSIONS:
        raise AuthorizationConfigError(f"not a global permission: {permission!r}")
    try:
        granted = GLOBAL_ROLE_PERMISSIONS[GlobalRole(role)]  # type: ignore[arg-type]
    except (ValueError, KeyError):
        raise AuthorizationConfigError(f"unknown global role: {role!r}") from None
    return permission in granted


class ResourceType(StrEnum):
    """Project-scoped resources. Each resolves to its project through its own
    rows (app/repositories/authz.py), never through a client-supplied id."""

    PROJECT = "project"
    TARGET = "target"
    TARGET_AUTHORIZATION = "target_authorization"
    ASSESSMENT = "assessment"
    RETEST_ASSESSMENT = "retest_assessment"
    SCAN = "scan"
    SCAN_LOG = "scan_log"
    ASSET = "asset"
    ENDPOINT = "endpoint"
    EVIDENCE = "evidence"
    ANALYSIS_RUN = "analysis_run"
    FINDING = "finding"
    REPORT = "report"
    REPORT_ARTIFACT = "report_artifact"
    REPORT_FINDING = "report_finding"
    REPORT_EVIDENCE = "report_evidence"
    COMPARISON = "comparison"
    COMPARISON_RECORD = "comparison_record"
    COMPARISON_COVERAGE_EVIDENCE = "comparison_coverage_evidence"
    RETEST_REPORT = "retest_report"
    RETEST_REPORT_ARTIFACT = "retest_report_artifact"
    RETEST_REPORT_EVIDENCE = "retest_report_evidence"

    @property
    def not_found(self) -> str:
        """The API's existing 404 detail for this resource ("scan not found").
        A retest is an assessment to API clients."""
        noun = "assessment" if self is ResourceType.RETEST_ASSESSMENT else self.value
        return f"{noun.replace('_', ' ')} not found"


@dataclass(frozen=True)
class AccessDecision:
    """An allowed request: who, which permission, and (for project
    permissions) which project and resource it was resolved from. Carries no
    lifecycle or business state: services still apply their own rules."""

    principal: "Principal"
    permission: Permission
    project_id: uuid.UUID | None = None
    role: ProjectRole | None = None
    resource_type: ResourceType | None = None
    resource_key: tuple[tuple[str, str], ...] = ()


# --- route access descriptors -------------------------------------------------------------


@dataclass(frozen=True)
class Public:
    """No authentication (health, login)."""


@dataclass(frozen=True)
class Authenticated:
    """Any authenticated principal. `allow_password_change_pending` only for
    the M2 account/session routes (me, logout, password)."""

    allow_password_change_pending: bool = False


@dataclass(frozen=True)
class GlobalAccess:
    permission: Permission


@dataclass(frozen=True)
class ProjectAccess:
    """A project permission on a resource identified by path parameters.
    `key` maps the resolver's key names to the route's path parameter names,
    e.g. {"id": "scan_id"} or {"report_id": "report_id", "format": "fmt"}."""

    permission: Permission
    resource_type: ResourceType
    key: Mapping[str, str] = field(default_factory=dict)


AccessDescriptor = Public | Authenticated | GlobalAccess | ProjectAccess
DESCRIPTOR_TYPES = (Public, Authenticated, GlobalAccess, ProjectAccess)
