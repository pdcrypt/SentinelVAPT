"""Route access declarations and the default-deny guard (ADR 0014, Phase 9 M3).

Every route declares exactly one descriptor through one of these dependency
factories:

    public()                                   no authentication (health, login)
    authenticated(allow_password_change_pending=False)
    require_global(Permission.USER_ADMIN)      a global permission
    authorize(Permission.SCAN_RUN, ResourceType.SCAN, parameter="scan_id")
    authorize(Permission.PROJECT_READ, ResourceType.REPORT_ARTIFACT,
              key={"report_id": "report_id", "format": "fmt"})

Order inside every protected dependency: authenticate (401) → password-change
gate (403 password_change_required) → resolve and authorize (404 / 403).
The gate runs before any resource lookup, so a pending-password principal
learns nothing about resources.

`require_access_descriptor` is the router-level guard for protected routers:
a route without exactly one known descriptor fails closed (logged 500).
M3 provides this machinery; M4 attaches it to the existing routes.
"""

from collections.abc import Callable, Iterator, Mapping
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Request
from fastapi.routing import APIRoute, RouteContext, iter_route_contexts

from app.api.deps import AuditContextDep, PrincipalDep, SessionDep
from app.core.authz import (
    DESCRIPTOR_TYPES,
    GLOBAL_PERMISSIONS,
    PROJECT_PERMISSIONS,
    AccessDecision,
    AccessDescriptor,
    Authenticated,
    AuthorizationConfigError,
    GlobalAccess,
    Permission,
    ProjectAccess,
    Public,
    ResourceType,
)
from app.core.errors import PasswordChangeRequiredError
from app.repositories.authz import RESOLVERS, ProjectResolver
from app.services.access import AccessService
from app.services.audit import AuditService
from app.services.auth import Principal

ACCESS_ATTR = "__sv_access__"


def get_access_service(session: SessionDep, context: AuditContextDep) -> AccessService:
    return AccessService(ProjectResolver(session), AuditService(session, context))


AccessServiceDep = Annotated[AccessService, Depends(get_access_service)]


def _mark[F: Callable[..., Any]](dependency: F, descriptor: AccessDescriptor) -> F:
    setattr(dependency, ACCESS_ATTR, descriptor)
    return dependency


def _password_gate(principal: Principal, access: AccessService, *, allow_pending: bool) -> None:
    if principal.must_change_password and not allow_pending:
        access.password_change_required(principal)  # recorded before the refusal
        raise PasswordChangeRequiredError()


def public() -> Callable[[], None]:
    def dependency() -> None:
        return None

    return _mark(dependency, Public())


def authenticated(*, allow_password_change_pending: bool = False) -> Callable[..., Principal]:
    def dependency(principal: PrincipalDep, access: AccessServiceDep) -> Principal:
        _password_gate(principal, access, allow_pending=allow_password_change_pending)
        return principal

    return _mark(dependency, Authenticated(allow_password_change_pending))


def require_global(permission: Permission) -> Callable[..., AccessDecision]:
    if not isinstance(permission, Permission) or permission not in GLOBAL_PERMISSIONS:
        raise AuthorizationConfigError(f"not a global permission: {permission!r}")

    def dependency(principal: PrincipalDep, access: AccessServiceDep) -> AccessDecision:
        _password_gate(principal, access, allow_pending=False)
        return access.authorize_global(principal, permission)

    return _mark(dependency, GlobalAccess(permission))


def authorize(
    permission: Permission,
    resource: ResourceType,
    parameter: str | None = None,
    *,
    key: Mapping[str, str] | None = None,
) -> Callable[..., AccessDecision]:
    """A project permission on the resource named by path parameters. Use
    `parameter` for single-id resources, `key` (resolver key → path
    parameter) for composite ones."""
    if not isinstance(permission, Permission) or permission not in PROJECT_PERMISSIONS:
        raise AuthorizationConfigError(f"not a project permission: {permission!r}")
    if not isinstance(resource, ResourceType) or resource not in RESOLVERS:
        raise AuthorizationConfigError(f"unknown resource type: {resource!r}")
    if (parameter is None) == (key is None):
        raise AuthorizationConfigError("give exactly one of parameter or key")
    mapping = dict(key) if key is not None else {"id": str(parameter)}
    if set(mapping) != set(RESOLVERS[resource].keys):
        raise AuthorizationConfigError(
            f"{resource.value} is identified by {RESOLVERS[resource].keys}, got {tuple(mapping)}"
        )
    frozen = dict(mapping)

    def dependency(
        request: Request, principal: PrincipalDep, access: AccessServiceDep
    ) -> AccessDecision:
        _password_gate(principal, access, allow_pending=False)
        values: dict[str, str] = {}
        for name, path_parameter in frozen.items():
            if path_parameter not in request.path_params:
                raise AuthorizationConfigError(f"route has no path parameter {path_parameter!r}")
            values[name] = str(request.path_params[path_parameter])
        return access.authorize_project(principal, permission, resource, values)

    return _mark(dependency, ProjectAccess(permission, resource, frozen))


# --- descriptor discovery and the default-deny guard ---------------------------------------


def _calls(dependant: Any) -> Iterator[Any]:
    for sub in getattr(dependant, "dependencies", ()):
        yield sub.call
        yield from _calls(sub)


def route_descriptors(route: Any) -> list[AccessDescriptor]:
    """Every access descriptor declared on a route itself (should be exactly
    one). Descriptors must be route-level: at request time the matched route
    (`scope["route"]`) is the route as declared, without include-time
    dependencies, so a descriptor given to include_router() is not seen and
    the request fails closed."""
    dependant = getattr(getattr(route, "original_route", route), "dependant", None)
    found: list[Any] = []
    seen: set[int] = set()
    for call in _calls(dependant):
        descriptor = getattr(call, ACCESS_ATTR, None)
        if descriptor is not None and id(call) not in seen:
            seen.add(id(call))
            found.append(descriptor)
    return found


def require_access_descriptor(request: Request) -> None:
    """Router-level guard for protected routers: the matched route must
    declare exactly one known descriptor, or the request fails closed."""
    route = request.scope.get("route")
    descriptors = route_descriptors(route) if route is not None else []
    if len(descriptors) != 1 or not isinstance(descriptors[0], DESCRIPTOR_TYPES):
        path = getattr(route, "path", "?")
        raise AuthorizationConfigError(
            f"route {path} declares {len(descriptors)} access descriptors; exactly one is required"
        )


def iter_api_routes(app: FastAPI) -> Iterator[RouteContext]:
    """Every API route of the app with its effective (included) path and
    dependencies; for the route-inventory meta-tests."""
    for context in iter_route_contexts(app.routes):
        if isinstance(context.original_route, APIRoute):
            yield context


def is_guarded(context: RouteContext) -> bool:
    """Whether the default-deny guard runs for the route (directly or through
    the router it was included with)."""
    return any(call is require_access_descriptor for call in _calls(context.dependant))
