import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
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
        # Referenced by scans' composite foreign key, which ties a scan to its
        # assessment's own target and authorization record.
        UniqueConstraint("id", "target_id", "authorization_id"),
        # Retests (ADR 0011). A retest's parent is an assessment of the same
        # target, and its baseline scan is a scan of that parent.
        UniqueConstraint("id", "target_id"),
        UniqueConstraint("id", "retest_of_assessment_id", "baseline_scan_id"),
        ForeignKeyConstraint(
            ["retest_of_assessment_id", "target_id"],
            ["assessments.id", "assessments.target_id"],
            name="fk_assessments_retest_of",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["baseline_scan_id", "retest_of_assessment_id", "target_id"],
            ["scans.id", "scans.assessment_id", "scans.target_id"],
            name="fk_assessments_baseline_scan",
            ondelete="RESTRICT",
            use_alter=True,  # scans reference assessments too
        ),
        CheckConstraint(
            "(retest_of_assessment_id IS NULL) = (baseline_scan_id IS NULL)",
            name="retest_pair",
        ),
        CheckConstraint(
            "retest_of_assessment_id IS NULL OR retest_of_assessment_id <> id",
            name="not_own_retest",
        ),
        # At most one live (not cancelled) retest per assessment.
        Index(
            "uq_assessments_one_live_retest",
            "retest_of_assessment_id",
            unique=True,
            postgresql_where=text("retest_of_assessment_id IS NOT NULL AND status <> 'cancelled'"),
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
    # Set once when a retest is created; a trigger keeps them immutable.
    retest_of_assessment_id: Mapped[uuid.UUID | None]
    baseline_scan_id: Mapped[uuid.UUID | None]

    target: Mapped["Target"] = relationship(back_populates="assessments")
    authorization: Mapped[TargetAuthorization] = relationship(
        primaryjoin=lambda: Assessment.authorization_id == TargetAuthorization.id,
        foreign_keys=lambda: [Assessment.authorization_id],
        viewonly=True,
    )
