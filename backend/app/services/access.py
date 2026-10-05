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

from collections.abc import Mapping

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
from app.services.auth import Principal


class AccessService:
    def __init__(self, resolver: ProjectResolver) -> None:
        self.resolver = resolver

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
        # Missing, other project and non-member are indistinguishable.
        if resolution is None or resolution.role is None:
            raise NotFoundError(resource.not_found)
        if not project_role_grants(resolution.role, permission):
            raise ForbiddenError()
        return AccessDecision(
            principal=principal,
            permission=permission,
            project_id=resolution.project_id,
            role=resolution.role,
            resource_type=resource,
            resource_key=tuple(sorted((k, str(v)) for k, v in key.items())),
        )

    def authorize_global(self, principal: Principal, permission: Permission) -> AccessDecision:
        if not isinstance(permission, Permission) or permission not in GLOBAL_PERMISSIONS:
            raise AuthorizationConfigError(f"not a global permission: {permission!r}")
        if not global_role_grants(principal.global_role, permission):
            raise ForbiddenError()
        return AccessDecision(principal=principal, permission=permission)
