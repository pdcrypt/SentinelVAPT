"""Project membership administration (ADR 0014, Phase 9 M7): project owners
only (membership.manage). The project is the authorized path; a member is
addressed as (project_id, user_id) and resolved from its own row, so a member
of another project is as invisible as a missing one."""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, status

from app.api.authz import authorize
from app.api.deps import AuditContextDep, SessionDep
from app.core.actors import UserActor
from app.core.authz import AccessDecision
from app.core.authz import Permission as P
from app.core.authz import ResourceType as R
from app.models import ProjectMember, User
from app.schemas.administration import MemberAdd, MemberRead, MembershipSelfRead, MemberUpdate
from app.services.audit import AuditService
from app.services.memberships import MembershipService

router = APIRouter(prefix="/projects/{project_id}/members", tags=["members"])
# The caller's own membership (M10): any member, about themselves only.
self_router = APIRouter(prefix="/projects/{project_id}/membership", tags=["members"])

ProjectMemberSelf = Annotated[
    AccessDecision, Depends(authorize(P.PROJECT_READ, R.PROJECT, "project_id"))
]
ProjectOwner = Annotated[
    AccessDecision, Depends(authorize(P.MEMBERSHIP_MANAGE, R.PROJECT, "project_id"))
]
MemberOwner = Annotated[
    AccessDecision,
    Depends(
        authorize(
            P.MEMBERSHIP_MANAGE,
            R.PROJECT_MEMBER,
            key={"project_id": "project_id", "user_id": "user_id"},
        )
    ),
]


def get_membership_service(session: SessionDep, context: AuditContextDep) -> MembershipService:
    return MembershipService(session, AuditService(session, context))


ServiceDep = Annotated[MembershipService, Depends(get_membership_service)]


def _read(member: ProjectMember, user: User) -> dict[str, Any]:
    return {
        "user_id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "role": member.role,
        "is_active": user.is_active,
        "created_by_user_id": member.created_by_user_id,
        "created_at": member.created_at,
    }


@router.get("", response_model=list[MemberRead])
def list_members(
    project_id: uuid.UUID, service: ServiceDep, access: ProjectOwner
) -> list[dict[str, Any]]:
    return [_read(m, u) for m, u in service.list(project_id)]


@router.post("", response_model=MemberRead, status_code=status.HTTP_201_CREATED)
def add_member(
    project_id: uuid.UUID, data: MemberAdd, service: ServiceDep, access: ProjectOwner
) -> dict[str, Any]:
    member, user = service.add(
        project_id, data.username, data.role, actor=UserActor.of(access.principal)
    )
    return _read(member, user)


@router.patch("/{user_id}", response_model=MemberRead)
def change_member_role(
    project_id: uuid.UUID,
    user_id: uuid.UUID,
    data: MemberUpdate,
    service: ServiceDep,
    access: MemberOwner,
) -> dict[str, Any]:
    member, user = service.change_role(
        project_id, user_id, data.role, actor=UserActor.of(access.principal)
    )
    return _read(member, user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    project_id: uuid.UUID, user_id: uuid.UUID, service: ServiceDep, access: MemberOwner
) -> None:
    service.remove(project_id, user_id, actor=UserActor.of(access.principal))


@self_router.get("/me", response_model=MembershipSelfRead)
def my_membership(
    project_id: uuid.UUID, service: ServiceDep, access: ProjectMemberSelf
) -> dict[str, Any]:
    """Your own role in the project, for display. The user is the signed-in
    one (there is no parameter to name another); non-members get 404. Reading
    it records nothing. It grants nothing: every request is authorized anew."""
    member = service.mine(project_id, access.principal.user_id)
    return {"project_id": member.project_id, "user_id": member.user_id, "role": member.role}
