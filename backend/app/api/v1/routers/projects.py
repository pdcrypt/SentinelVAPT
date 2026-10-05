import uuid
from collections.abc import Sequence
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.authz import authenticated, authorize, require_global
from app.api.deps import Limit, Offset, ProjectServiceDep
from app.core.authz import AccessDecision
from app.core.authz import Permission as P
from app.core.authz import ResourceType as R
from app.models import Project
from app.schemas.project import ProjectCreate, ProjectRead, ProjectUpdate
from app.services.auth import Principal

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(
    data: ProjectCreate,
    service: ProjectServiceDep,
    access: Annotated[AccessDecision, Depends(require_global(P.PROJECT_CREATE))],
) -> Project:
    """The authenticated user becomes the project's first owner, in the same
    transaction. Nothing in the body names an owner."""
    return service.create(data, owner_id=access.principal.user_id)


@router.get("", response_model=list[ProjectRead])
def list_projects(
    service: ProjectServiceDep,
    principal: Annotated[Principal, Depends(authenticated())],
    limit: Limit = 50,
    offset: Offset = 0,
) -> Sequence[Project]:
    """Only the projects the caller is a member of (whatever their global role)."""
    return service.list_for_member(principal.user_id, limit=limit, offset=offset)


@router.get(
    "/{project_id}",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.PROJECT, "project_id"))],
    response_model=ProjectRead,
)
def get_project(project_id: uuid.UUID, service: ProjectServiceDep) -> Project:
    return service.get(project_id)


@router.patch("/{project_id}", response_model=ProjectRead)
def update_project(
    project_id: uuid.UUID,
    data: ProjectUpdate,
    service: ProjectServiceDep,
    access: Annotated[
        AccessDecision, Depends(authorize(P.PROJECT_UPDATE, R.PROJECT, "project_id"))
    ],
) -> Project:
    return service.update(project_id, data, member_id=access.principal.user_id)


@router.delete(
    "/{project_id}",
    dependencies=[Depends(authorize(P.PROJECT_DELETE, R.PROJECT, "project_id"))],
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_project(project_id: uuid.UUID, service: ProjectServiceDep) -> None:
    service.delete(project_id)
