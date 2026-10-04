import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum_column
from app.models.enums import AssessmentStatus
from app.models.target_authorization import TargetAuthorization

if TYPE_CHECKING:
    from app.models.target import Target


class Assessment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One engagement against one target (ADR 0003). The project is reached
    through the target, so there is no separate project_id to drift.

    `authorization_id` records the exact authorization (and therefore scope)
    the assessment was planned under; the database guarantees it belongs to
    the same target.
    """

    __tablename__ = "assessments"
    __table_args__ = (
        CheckConstraint(
            "completed_at IS NULL OR started_at IS NOT NULL",
            name="completed_requires_started",
        ),
        ForeignKeyConstraint(
            ["authorization_id", "target_id"],
            ["target_authorizations.id", "target_authorizations.target_id"],
            name="fk_assessments_authorization",
            ondelete="RESTRICT",
        ),
    )

    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="RESTRICT"), index=True
    )
    authorization_id: Mapped[uuid.UUID]
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[AssessmentStatus] = mapped_column(
        str_enum_column(AssessmentStatus, "assessment_status"),
        default=AssessmentStatus.PLANNED,
        server_default=AssessmentStatus.PLANNED.value,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(200))

    target: Mapped["Target"] = relationship(back_populates="assessments")
    authorization: Mapped[TargetAuthorization] = relationship(
        primaryjoin=lambda: Assessment.authorization_id == TargetAuthorization.id,
        foreign_keys=lambda: [Assessment.authorization_id],
        viewonly=True,
    )
