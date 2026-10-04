import uuid
from collections.abc import Sequence

from app.core.errors import ConflictError, NotFoundError
from app.models import Project
from app.repositories import ProjectRepository
from app.schemas.project import ProjectCreate, ProjectUpdate
from app.services.base import UnitOfWork


class ProjectService:
    def __init__(self, projects: ProjectRepository, uow: UnitOfWork) -> None:
        self.projects = projects
        self.uow = uow

    def create(self, data: ProjectCreate) -> Project:
        self._ensure_name_available(data.name)
        project = self.projects.add(Project(name=data.name, description=data.description))
        self.uow.commit()
        return project

    def get(self, project_id: uuid.UUID) -> Project:
        project = self.projects.get(project_id)
        if project is None:
            raise NotFoundError("project not found")
        return project

    def list(self, *, limit: int, offset: int) -> Sequence[Project]:
        return self.projects.list(limit=limit, offset=offset)

    def update(self, project_id: uuid.UUID, data: ProjectUpdate) -> Project:
        project = self.get(project_id)
        changes = data.model_dump(exclude_unset=True)
        if "name" in changes and changes["name"] != project.name:
            self._ensure_name_available(changes["name"], exclude_id=project.id)
        for field, value in changes.items():
            setattr(project, field, value)
        self.projects.flush()
        self.uow.commit()
        return project

    def delete(self, project_id: uuid.UUID) -> None:
        project = self.get(project_id)
        if self.projects.has_targets(project.id):
            raise ConflictError("project still has targets; delete them first")
        self.projects.delete(project)
        self.uow.commit()

    def _ensure_name_available(self, name: str, *, exclude_id: uuid.UUID | None = None) -> None:
        if self.projects.name_exists(name, exclude_id=exclude_id):
            raise ConflictError(f"a project named '{name}' already exists", field="name")
