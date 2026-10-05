import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.authz import AccessServiceDep, authorize
from app.api.deps import Limit, Offset, TargetServiceDep
from app.core.actors import UserActor
from app.core.authz import AccessDecision
from app.core.authz import Permission as P
from app.core.authz import ResourceType as R
from app.models import Target
from app.schemas.target import (
    TargetAuthorizationRead,
    TargetCreate,
    TargetRead,
    TargetUpdate,
)
from app.services.targets import TargetService

router = APIRouter(tags=["targets"])


def _read(target: Target, service: TargetService) -> TargetRead:
    return TargetRead.from_model(target, service.authorization_status(target.current_authorization))


@router.post(
    "/projects/{project_id}/targets",
    response_model=TargetRead,
    status_code=status.HTTP_201_CREATED,
)
def create_target(
    project_id: uuid.UUID,
    data: TargetCreate,
    service: TargetServiceDep,
    access: Annotated[AccessDecision, Depends(authorize(P.TARGET_MANAGE, R.PROJECT, "project_id"))],
    access_service: AccessServiceDep,
) -> TargetRead:
    # A new target always carries an authorization acknowledgment. Project
    # membership never stands in for it: the acknowledgment itself is still
    # validated and recorded by the target service (Phase 1), attributed to the
    # authenticated user (Phase 9 M5).
    access_service.require_also(access, P.TARGET_AUTHORIZE)
    return _read(service.create(project_id, data, actor=UserActor.of(access.principal)), service)


@router.get(
    "/projects/{project_id}/targets",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.PROJECT, "project_id"))],
    response_model=list[TargetRead],
)
def list_targets(
    project_id: uuid.UUID, service: TargetServiceDep, limit: Limit = 50, offset: Offset = 0
) -> list[TargetRead]:
    targets = service.list_for_project(project_id, limit=limit, offset=offset)
    return [_read(t, service) for t in targets]


@router.get(
    "/targets/{target_id}",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.TARGET, "target_id"))],
    response_model=TargetRead,
)
def get_target(target_id: uuid.UUID, service: TargetServiceDep) -> TargetRead:
    return _read(service.get(target_id), service)


@router.patch("/targets/{target_id}", response_model=TargetRead)
def update_target(
    target_id: uuid.UUID,
    data: TargetUpdate,
    service: TargetServiceDep,
    access: Annotated[AccessDecision, Depends(authorize(P.TARGET_MANAGE, R.TARGET, "target_id"))],
    access_service: AccessServiceDep,
) -> TargetRead:
    if data.authorization is not None:
        access_service.require_also(access, P.TARGET_AUTHORIZE)
    return _read(service.update(target_id, data, actor=UserActor.of(access.principal)), service)


@router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    target_id: uuid.UUID,
    service: TargetServiceDep,
    access: Annotated[AccessDecision, Depends(authorize(P.TARGET_MANAGE, R.TARGET, "target_id"))],
) -> None:
    service.delete(target_id, actor=UserActor.of(access.principal))


@router.get(
    "/targets/{target_id}/authorizations",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.TARGET, "target_id"))],
    response_model=list[TargetAuthorizationRead],
)
def list_target_authorizations(
    target_id: uuid.UUID, service: TargetServiceDep, limit: Limit = 50, offset: Offset = 0
) -> list[TargetAuthorizationRead]:
    """Append-only authorization history, newest first. Read-only by design."""
    target = service.get(target_id)
    records = service.list_authorizations(target_id, limit=limit, offset=offset)
    return [
        TargetAuthorizationRead.from_model(
            r,
            status=service.authorization_status(r),
            is_current=r.id == target.current_authorization_id,
        )
        for r in records
    ]
