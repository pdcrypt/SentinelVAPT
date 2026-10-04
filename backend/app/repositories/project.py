import uuid
from collections.abc import Sequence

from sqlalchemy import exists, select

from app.models import Project, Target
from app.repositories.base import SqlRepository


class ProjectRepository(SqlRepository[Project]):
    model = Project

    def list(self, *, limit: int, offset: int) -> Sequence[Project]:
        stmt = select(Project).order_by(Project.created_at, Project.id).limit(limit).offset(offset)
        return self.session.scalars(stmt).all()

    def name_exists(self, name: str, *, exclude_id: uuid.UUID | None = None) -> bool:
        stmt = select(exists().where(Project.name == name, Project.id != exclude_id))
        return bool(self.session.scalar(stmt))

    def has_targets(self, project_id: uuid.UUID) -> bool:
        return bool(self.session.scalar(select(exists().where(Target.project_id == project_id))))
