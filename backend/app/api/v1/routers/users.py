"""Account administration (ADR 0014, Phase 9 M7): global administrators
only (user.admin). Users are global, not project resources: an id that is
malformed or unknown is simply "user not found"."""

from collections.abc import Sequence
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.authz import require_global
from app.api.deps import AuditContextDep, ClockDep, Limit, Offset, SessionDep, get_passwords
from app.core.actors import UserActor
from app.core.authz import AccessDecision
from app.core.authz import Permission as P
from app.core.passwords import Passwords
from app.models import User
from app.models.enums import GlobalRole
from app.schemas.administration import PasswordReset, UserCreate, UserRead
from app.services.audit import AuditService
from app.services.users import UserAdministrationService, parse_user_id

router = APIRouter(prefix="/users", tags=["users"])

AdminDep = Annotated[AccessDecision, Depends(require_global(P.USER_ADMIN))]


def get_user_administration(
    session: SessionDep,
    clock: ClockDep,
    passwords: Annotated[Passwords, Depends(get_passwords)],
    context: AuditContextDep,
) -> UserAdministrationService:
    return UserAdministrationService(session, clock, passwords, AuditService(session, context))


ServiceDep = Annotated[UserAdministrationService, Depends(get_user_administration)]


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(data: UserCreate, service: ServiceDep, access: AdminDep) -> User:
    """Create an account with a temporary password (changed at first sign-in)."""
    return service.create(
        data.username,
        data.display_name,
        data.password,
        data.global_role,
        actor=UserActor.of(access.principal),
    )


@router.get("", response_model=list[UserRead])
def list_users(
    service: ServiceDep,
    access: AdminDep,
    active: bool | None = None,
    global_role: GlobalRole | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Sequence[User]:
    return service.list(active=active, global_role=global_role, limit=limit, offset=offset)


@router.get("/{user_id}", response_model=UserRead)
def get_user(user_id: str, service: ServiceDep, access: AdminDep) -> User:
    return service.get(parse_user_id(user_id))


@router.post("/{user_id}/disable", response_model=UserRead)
def disable_user(user_id: str, service: ServiceDep, access: AdminDep) -> User:
    """Disable the account and revoke all its sessions. Users are never deleted."""
    return service.disable(parse_user_id(user_id), actor=UserActor.of(access.principal))


@router.post("/{user_id}/password-reset", response_model=UserRead)
def reset_password(
    user_id: str, data: PasswordReset, service: ServiceDep, access: AdminDep
) -> User:
    """Set a temporary password, revoke all sessions, require a change."""
    return service.reset_password(
        parse_user_id(user_id), data.new_password, actor=UserActor.of(access.principal)
    )
