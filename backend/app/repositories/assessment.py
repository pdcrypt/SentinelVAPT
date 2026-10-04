import uuid
from collections.abc import Sequence

from sqlalchemy import select

from app.models import Assessment, Target
from app.repositories.base import SqlRepository


class AssessmentRepository(SqlRepository[Assessment]):
    model = Assessment

    def get_for_update(self, assessment_id: uuid.UUID) -> Assessment | None:
        """Load an assessment and lock its row (SELECT ... FOR UPDATE) until the
        transaction ends, so concurrent lifecycle operations on it serialize and
        each one decides on the state the previous one committed.

        No joins: relationships load lazily in separate statements (see
        TargetRepository.get_for_update for why a joined lock query is unsafe).
        populate_existing replaces anything this session had cached.
        """
        stmt = (
            select(Assessment)
            .where(Assessment.id == assessment_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return self.session.scalars(stmt).one_or_none()

    def list_for_target(
        self, target_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[Assessment]:
        stmt = (
            select(Assessment)
            .where(Assessment.target_id == target_id)
            .order_by(Assessment.created_at, Assessment.id)
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()

    def list_for_project(
        self, project_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[Assessment]:
        stmt = (
            select(Assessment)
            .join(Target, Assessment.target_id == Target.id)
            .where(Target.project_id == project_id)
            .order_by(Assessment.created_at, Assessment.id)
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()
