import uuid
from collections.abc import Sequence

from sqlalchemy import exists, select
from sqlalchemy.orm import lazyload

from app.models import Assessment, Target, TargetAuthorization
from app.repositories.base import SqlRepository


class TargetRepository(SqlRepository[Target]):
    model = Target

    def get_for_update(self, target_id: uuid.UUID) -> Target | None:
        """Load a target and lock its row (SELECT ... FOR UPDATE) until the
        transaction ends, so concurrent changes to the same target serialize.

        The lock query must not join the current authorization: if a concurrent
        transaction changes current_authorization_id while we wait, PostgreSQL
        re-checks the locked row against the *old* joined row, the join no
        longer matches and the target silently vanishes from the result.
        Instead the authorization is loaded by a separate statement after the
        lock is held, which sees the latest committed record.

        populate_existing makes values read after acquiring the lock replace
        anything this session had cached.
        """
        stmt = (
            select(Target)
            .where(Target.id == target_id)
            .options(lazyload(Target.current_authorization))
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        target = self.session.scalars(stmt).one_or_none()
        if target is not None:
            self.session.expire(target, ["current_authorization"])
        return target

    def set_current_authorization(self, target: Target, authorization: TargetAuthorization) -> None:
        target.current_authorization_id = authorization.id
        self.session.flush()
        # The relationship is view-only; reload it so callers see the new record.
        self.session.expire(target, ["current_authorization"])

    def list_for_project(
        self, project_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[Target]:
        stmt = (
            select(Target)
            .where(Target.project_id == project_id)
            .order_by(Target.created_at, Target.id)
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()

    def name_exists(
        self, project_id: uuid.UUID, name: str, *, exclude_id: uuid.UUID | None = None
    ) -> bool:
        stmt = select(
            exists().where(
                Target.project_id == project_id, Target.name == name, Target.id != exclude_id
            )
        )
        return bool(self.session.scalar(stmt))

    def has_assessments(self, target_id: uuid.UUID) -> bool:
        return bool(self.session.scalar(select(exists().where(Assessment.target_id == target_id))))
