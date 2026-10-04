import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum_column
from app.models.enums import ScanStatus


class Scan(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One execution of discovery for an assessment.

    The composite foreign key ties a scan to its assessment's own target and
    authorization record, so a scan can never reference another target's
    authorization. `grant_snapshot` is an audit record of what the scanner was
    given; it is never read back as authorization state (ADR 0008).
    """

    __tablename__ = "scans"
    __table_args__ = (
        ForeignKeyConstraint(
            ["assessment_id", "target_id", "authorization_id"],
            ["assessments.id", "assessments.target_id", "assessments.authorization_id"],
            name="fk_scans_assessment",
            ondelete="RESTRICT",
        ),
        # At most one queued or running scan per assessment.
        Index(
            "uq_scans_one_active_per_assessment",
            "assessment_id",
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
        Index("ix_scans_assessment_id_created_at", "assessment_id", "created_at"),
        # Target of findings' composite foreign key.
        UniqueConstraint("id", "assessment_id", "target_id"),
        Index("ix_scans_status_created_at", "status", "created_at"),
        CheckConstraint("status <> 'queued' OR started_at IS NULL", name="queued_not_started"),
        CheckConstraint(
            "status NOT IN ('running', 'completed') OR started_at IS NOT NULL",
            name="running_requires_started",
        ),
        CheckConstraint(
            "status <> 'running' OR claimed_by IS NOT NULL", name="running_requires_worker"
        ),
        CheckConstraint(
            "(status IN ('completed', 'failed', 'cancelled')) = (finished_at IS NOT NULL)",
            name="finished_iff_terminal",
        ),
    )

    assessment_id: Mapped[uuid.UUID]
    target_id: Mapped[uuid.UUID]
    authorization_id: Mapped[uuid.UUID]
    status: Mapped[ScanStatus] = mapped_column(
        str_enum_column(ScanStatus, "scan_status"),
        default=ScanStatus.QUEUED,
        server_default=ScanStatus.QUEUED.value,
    )
    stop_reason: Mapped[str | None] = mapped_column(String(32))

    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_reason: Mapped[str | None] = mapped_column(String(64))
    claimed_by: Mapped[str | None] = mapped_column(String(200))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(String(1000))

    scanner_version: Mapped[str | None] = mapped_column(String(32))
    config: Mapped[dict[str, Any]] = mapped_column(JSONB)
    grant_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    requests_sent: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    pages_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    endpoints_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    events_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    evidence_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    created_by: Mapped[str | None] = mapped_column(String(200))
