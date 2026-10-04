import uuid
from collections.abc import Sequence

from sqlalchemy import select

from app.models import TargetAuthorization
from app.repositories.base import SqlRepository


class TargetAuthorizationRepository(SqlRepository[TargetAuthorization]):
    """Append-only: records are added and read, never updated or deleted."""

    model = TargetAuthorization

    def list_for_target(
        self, target_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[TargetAuthorization]:
        stmt = (
            select(TargetAuthorization)
            .where(TargetAuthorization.target_id == target_id)
            .order_by(TargetAuthorization.version.desc())
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()
