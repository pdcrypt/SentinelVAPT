import uuid
from collections.abc import Sequence

from fastapi import APIRouter, status

from app.api.deps import Limit, Offset, ProjectServiceDep
from app.models import Project
from app.schemas.project import ProjectCreate, ProjectRead, ProjectUpdate

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(data: ProjectCreate, service: ProjectServiceDep) -> Project:
    return service.create(data)


@router.get("", response_model=list[ProjectRead])
def list_projects(
    service: ProjectServiceDep, limit: Limit = 50, offset: Offset = 0
) -> Sequence[Project]:
    return service.list(limit=limit, offset=offset)


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(project_id: uuid.UUID, service: ProjectServiceDep) -> Project:
    return service.get(project_id)


@router.patch("/{project_id}", response_model=ProjectRead)
def update_project(
    project_id: uuid.UUID, data: ProjectUpdate, service: ProjectServiceDep
) -> Project:
    return service.update(project_id, data)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: uuid.UUID, service: ProjectServiceDep) -> None:
    service.delete(project_id)
