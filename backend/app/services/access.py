"""Authorization decisions (ADR 0014, Phase 9 M3).

    principal → resource → its project (resolver) → caller's membership →
    role table → allow (AccessDecision) | 404 | 403

- A missing resource, a resource of another project and a project the caller
  is not a member of all give the same 404 with the API's existing body
  ("scan not found"): existence is never revealed across projects.
- Only a member whose role lacks the permission gets 403.
- Global permissions come from the global role and never touch projects. The
  global `admin` role grants no project permission; project access exists
  only through `project_members`.
- Lifecycle and target-authorization rules are not decided here: services
  keep applying them after authorization.
"""

import uuid
from collections.abc import Mapping

from app.core.actors import UserActor
from app.core.audit import AuditAction
from app.core.authz import (
    GLOBAL_PERMISSIONS,
    PROJECT_PERMISSIONS,
    AccessDecision,
    AuthorizationConfigError,
    Permission,
    ResourceType,
    global_role_grants,
    project_role_grants,
)
from app.core.errors import ForbiddenError, NotFoundError
from app.repositories.authz import ProjectResolver
from app.services.audit import AuditService
from app.services.auth import Principal

# The resource an audit event names for a composite key: its parent.
_AUDIT_PARENT: Mapping[ResourceType, tuple[ResourceType, str]] = {
    ResourceType.ASSESSMENT_COMPARISON: (ResourceType.ASSESSMENT, "assessment_id"),
    ResourceType.COMPARISON_RECORD: (ResourceType.COMPARISON, "comparison_id"),
    ResourceType.COMPARISON_COVERAGE_EVIDENCE: (ResourceType.COMPARISON, "comparison_id"),
    ResourceType.REPORT_ARTIFACT: (ResourceType.REPORT, "report_id"),
    ResourceType.REPORT_FINDING: (ResourceType.REPORT, "report_id"),
    ResourceType.REPORT_EVIDENCE: (ResourceType.REPORT, "report_id"),
    ResourceType.RETEST_REPORT_ARTIFACT: (ResourceType.RETEST_REPORT, "report_id"),
    ResourceType.RETEST_REPORT_EVIDENCE: (ResourceType.RETEST_REPORT, "report_id"),
}


def _audit_resource(
    resource: ResourceType, key: Mapping[str, str]
) -> tuple[ResourceType, uuid.UUID]:
    kind, name = _AUDIT_PARENT.get(resource, (resource, "id"))
    return kind, uuid.UUID(str(key[name]))


class AccessService:
    """Decides access and records the security-relevant refusals (M6):
    a member without the permission (403), a non-member reaching for a
    resource that exists in another project (404), a missing global
    permission (403) and the password-change gate. A resource that does not
    exist is an ordinary 404 and is not recorded."""

    def __init__(self, resolver: ProjectResolver, audit: AuditService) -> None:
        self.resolver = resolver
        self.audit = audit

    def _deny(
        self,
        principal: Principal,
        permission: Permission,
        reason: str,
        *,
        resource: tuple[ResourceType, uuid.UUID] | None = None,
        role: str | None = None,
    ) -> None:
        self.audit.denial(
            AuditAction.AUTHZ_DENIED,
            UserActor.of(principal),
            resource=resource,
            metadata={"permission": permission.value, "reason": reason, "role": role},
        )

    def password_change_required(self, principal: Principal) -> None:
        self.audit.denial(AuditAction.AUTH_PASSWORD_CHANGE_REQUIRED, UserActor.of(principal))

    def authorize_project(
        self,
        principal: Principal,
        permission: Permission,
        resource: ResourceType,
        key: Mapping[str, str],
    ) -> AccessDecision:
        if not isinstance(permission, Permission) or permission not in PROJECT_PERMISSIONS:
            raise AuthorizationConfigError(f"not a project permission: {permission!r}")
        if not isinstance(resource, ResourceType):
            raise AuthorizationConfigError(f"unknown resource type: {resource!r}")
        resolution = self.resolver.resolve(resource, key, principal.user_id)
        # Missing, other project and non-member are indistinguishable to the
        # caller; only the latter two are recorded.
        if resolution is None:
            raise NotFoundError(resource.not_found)
        if resolution.role is None:
            self._deny(principal, permission, "not_member", resource=_audit_resource(resource, key))
            raise NotFoundError(resource.not_found)
        if not project_role_grants(resolution.role, permission):
            self._deny(
                principal,
                permission,
                "insufficient_role",
                resource=_audit_resource(resource, key),
                role=resolution.role.value,
            )
            raise ForbiddenError()
        return AccessDecision(
            principal=principal,
            permission=permission,
            project_id=resolution.project_id,
            role=resolution.role,
            resource_type=resource,
            resource_key=tuple(sorted((k, str(v)) for k, v in key.items())),
        )

    def require_also(self, decision: AccessDecision, permission: Permission) -> None:
        """A further project permission for an already-authorized request
        (e.g. acknowledging a target authorization while updating the
        target): same project, same role, no new lookup."""
        if decision.role is None or decision.project_id is None or decision.resource_type is None:
            raise AuthorizationConfigError("require_also needs a project decision")
        if not project_role_grants(decision.role, permission):
            key = dict(decision.resource_key)
            self._deny(
                decision.principal,
                permission,
                "insufficient_role",
                resource=_audit_resource(decision.resource_type, key),
                role=decision.role.value,
            )
            raise ForbiddenError()

    def authorize_global(self, principal: Principal, permission: Permission) -> AccessDecision:
        if not isinstance(permission, Permission) or permission not in GLOBAL_PERMISSIONS:
            raise AuthorizationConfigError(f"not a global permission: {permission!r}")
        if not global_role_grants(principal.global_role, permission):
            self._deny(
                principal, permission, "insufficient_global_role", role=str(principal.global_role)
            )
            raise ForbiddenError()
        return AccessDecision(principal=principal, permission=permission)
