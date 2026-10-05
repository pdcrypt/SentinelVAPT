import uuid
from collections.abc import Sequence

from sqlalchemy import ColumnElement, exists, func, select

from app.models import Project, ProjectMember, Target
from app.models.enums import ProjectRole
from app.repositories.base import SqlRepository


def _scope(member_id: uuid.UUID | None) -> ColumnElement[bool]:
    """Projects the user is a member of; for None, projects with no members
    (legacy or created by a server-side command)."""
    if member_id is None:
        return ~exists().where(ProjectMember.project_id == Project.id)
    return exists().where(ProjectMember.project_id == Project.id,
                          ProjectMember.user_id == member_id)  # fmt: skip


class ProjectRepository(SqlRepository[Project]):
    model = Project

    def list_for_member(
        self, member_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[Project]:
        """Only the projects the user is a member of (ADR 0014): a global
        role, knowing an id or having no members exposes nothing."""
        stmt = (
            select(Project)
            .where(_scope(member_id))
            .order_by(Project.created_at, Project.id)
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()

    def lock_names(self, member_id: uuid.UUID | None) -> None:
        """Serializes name checks within one name scope (there is no unique
        constraint: names are unique per member, see name_exists)."""
        key = f"project_names:{member_id or 'unowned'}"
        self.session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(key, 0))))

    def name_exists(
        self, name: str, *, member_id: uuid.UUID | None, exclude_id: uuid.UUID | None = None
    ) -> bool:
        """Whether a project of that name exists among the user's projects.
        Names of projects the user cannot see are never revealed (M4)."""
        stmt = select(
            exists().where(Project.name == name, Project.id != exclude_id, _scope(member_id))
        )
        return bool(self.session.scalar(stmt))

    def add_owner(self, project_id: uuid.UUID, user_id: uuid.UUID) -> None:
        self.session.add(
            ProjectMember(
                project_id=project_id,
                user_id=user_id,
                role=ProjectRole.OWNER,
                created_by_user_id=user_id,
            )
        )

    def has_targets(self, project_id: uuid.UUID) -> bool:
        return bool(self.session.scalar(select(exists().where(Target.project_id == project_id))))
