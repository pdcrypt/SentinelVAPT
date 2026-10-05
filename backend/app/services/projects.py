import uuid
from collections.abc import Sequence

from app.core.errors import ConflictError, NotFoundError
from app.models import Project
from app.repositories import ProjectRepository
from app.schemas.project import ProjectCreate, ProjectUpdate
from app.services.base import UnitOfWork


class ProjectService:
    """Projects. Access is decided before these methods run (app/api/authz.py);
    `member_id` is always the authenticated user, never request data."""

    def __init__(self, projects: ProjectRepository, uow: UnitOfWork) -> None:
        self.projects = projects
        self.uow = uow

    def create(self, data: ProjectCreate, *, owner_id: uuid.UUID | None) -> Project:
        """Creates the project and, in the same transaction, makes `owner_id`
        its first owner. `owner_id=None` (server-side commands and tests
        only) leaves it without members: it is then visible to nobody until
        it is explicitly claimed (python -m app.cli claim-project)."""
        self.projects.lock_names(owner_id)
        self._ensure_name_available(data.name, member_id=owner_id)
        project = self.projects.add(Project(name=data.name, description=data.description))
        if owner_id is not None:
            self.projects.add_owner(project.id, owner_id)
            self.projects.flush()
        self.uow.commit()
        return project

    def get(self, project_id: uuid.UUID) -> Project:
        project = self.projects.get(project_id)
        if project is None:
            raise NotFoundError("project not found")
        return project

    def list_for_member(
        self, member_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[Project]:
        return self.projects.list_for_member(member_id, limit=limit, offset=offset)

    def update(
        self, project_id: uuid.UUID, data: ProjectUpdate, *, member_id: uuid.UUID
    ) -> Project:
        project = self.get(project_id)
        changes = data.model_dump(exclude_unset=True)
        if "name" in changes and changes["name"] != project.name:
            self.projects.lock_names(member_id)
            self._ensure_name_available(changes["name"], member_id=member_id, exclude_id=project.id)
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

    def _ensure_name_available(
        self, name: str, *, member_id: uuid.UUID | None, exclude_id: uuid.UUID | None = None
    ) -> None:
        if self.projects.name_exists(name, member_id=member_id, exclude_id=exclude_id):
            raise ConflictError(f"a project named '{name}' already exists", field="name")
