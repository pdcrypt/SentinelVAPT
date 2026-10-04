import uuid

from fastapi import APIRouter, status

from app.api.deps import Limit, Offset, TargetServiceDep
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
    project_id: uuid.UUID, data: TargetCreate, service: TargetServiceDep
) -> TargetRead:
    return _read(service.create(project_id, data), service)


@router.get("/projects/{project_id}/targets", response_model=list[TargetRead])
def list_targets(
    project_id: uuid.UUID, service: TargetServiceDep, limit: Limit = 50, offset: Offset = 0
) -> list[TargetRead]:
    targets = service.list_for_project(project_id, limit=limit, offset=offset)
    return [_read(t, service) for t in targets]


@router.get("/targets/{target_id}", response_model=TargetRead)
def get_target(target_id: uuid.UUID, service: TargetServiceDep) -> TargetRead:
    return _read(service.get(target_id), service)


@router.patch("/targets/{target_id}", response_model=TargetRead)
def update_target(
    target_id: uuid.UUID, data: TargetUpdate, service: TargetServiceDep
) -> TargetRead:
    return _read(service.update(target_id, data), service)


@router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(target_id: uuid.UUID, service: TargetServiceDep) -> None:
    service.delete(target_id)


@router.get("/targets/{target_id}/authorizations", response_model=list[TargetAuthorizationRead])
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
