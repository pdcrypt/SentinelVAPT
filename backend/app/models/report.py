"""Phase 5 reports (ADR 0010).

- reports: one report of one assessment and one completed, analysed scan. Its
  snapshot (everything the report shows) is frozen when it is requested;
  rendering is a pure function of that snapshot.
- report_artifacts: the rendered JSON / HTML / PDF bytes, hashed, at most
  25 MB each. Written once, by the worker that generated the report.
- report_findings / report_evidence: the findings and evidence a report
  includes, tied to the report's own scan by composite foreign keys, so the
  records a report cites can never be removed or swapped.

Database triggers make reports, artifacts and these links immutable once
written (see the migration); a completed report never changes.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    Sequence,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum_column
from app.models.enums import ReportClassification, ReportKind, ReportStatus

MAX_ARTIFACT_BYTES = 25 * 1024 * 1024

# Human-facing report numbers (SV-R-000042). Gaps are possible (a rolled-back
# request consumes a number); numbers are never reused.
report_number_seq = Sequence("report_number_seq", metadata=Base.metadata)

_SHA256 = "~ '^[0-9a-f]{64}$'"


class Report(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint("number"),
        UniqueConstraint("id", "scan_id"),  # target of the link tables' composite keys
        ForeignKeyConstraint(
            ["scan_id", "assessment_id", "target_id"],
            ["scans.id", "scans.assessment_id", "scans.target_id"],
            name="fk_reports_scan",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["analysis_run_id", "scan_id"],
            ["analysis_runs.id", "analysis_runs.scan_id"],
            name="fk_reports_analysis_run",
            ondelete="RESTRICT",
        ),
        Index("ix_reports_assessment_id_created_at", "assessment_id", "created_at"),
        Index("ix_reports_status_created_at", "status", "created_at"),
        CheckConstraint("number >= 1", name="number_positive"),
        CheckConstraint(
            "(status IN ('completed', 'failed')) = (finished_at IS NOT NULL)",
            name="finished_iff_terminal",
        ),
        CheckConstraint("(status = 'failed') = (error_code IS NOT NULL)", name="error_iff_failed"),
        CheckConstraint(
            "status = 'queued' OR (claimed_by IS NOT NULL AND claimed_at IS NOT NULL)",
            name="claimed_unless_queued",
        ),
        CheckConstraint(
            "cardinality(formats) BETWEEN 1 AND 3 "
            "AND formats <@ ARRAY['json', 'html', 'pdf']::varchar[] "
            "AND 'json' = ANY(formats)",
            name="formats_valid",
        ),
        CheckConstraint(f"snapshot_sha256 {_SHA256}", name="snapshot_sha256_hex"),
        CheckConstraint(f"content_sha256 {_SHA256}", name="content_sha256_hex"),
        CheckConstraint(f"template_hash {_SHA256}", name="template_hash_hex"),
        CheckConstraint("template_version >= 1", name="template_version_positive"),
    )

    number: Mapped[int] = mapped_column(Integer)
    assessment_id: Mapped[uuid.UUID]
    target_id: Mapped[uuid.UUID]
    scan_id: Mapped[uuid.UUID]
    analysis_run_id: Mapped[uuid.UUID]
    kind: Mapped[ReportKind] = mapped_column(str_enum_column(ReportKind, "report_kind"))
    status: Mapped[ReportStatus] = mapped_column(
        str_enum_column(ReportStatus, "report_status"),
        default=ReportStatus.QUEUED,
        server_default=ReportStatus.QUEUED.value,
    )
    title: Mapped[str] = mapped_column(String(200))
    prepared_by: Mapped[str] = mapped_column(String(200))
    # Who requested it (M5, server-set; NULL before M5). The worker that
    # performs it is recorded separately (claimed_by) and never changes this.
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT")
    )
    reviewed_by: Mapped[str | None] = mapped_column(String(200))
    classification: Mapped[ReportClassification] = mapped_column(
        str_enum_column(ReportClassification, "report_classification")
    )
    formats: Mapped[list[str]] = mapped_column(ARRAY(String(8)))
    template_id: Mapped[str] = mapped_column(String(64))
    template_version: Mapped[int] = mapped_column(Integer)
    template_hash: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[str] = mapped_column(String(64))
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    content_sha256: Mapped[str] = mapped_column(String(64))
    claimed_by: Mapped[str | None] = mapped_column(String(200))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))

    @property
    def display_number(self) -> str:
        return f"SV-R-{self.number:06d}"


class ReportArtifact(Base):
    __tablename__ = "report_artifacts"
    __table_args__ = (
        PrimaryKeyConstraint("report_id", "format"),
        ForeignKeyConstraint(
            ["report_id"],
            ["reports.id"],
            name="fk_report_artifacts_report",
            ondelete="RESTRICT",
        ),
        CheckConstraint("format IN ('json', 'html', 'pdf')", name="format_valid"),
        CheckConstraint(f"size_bytes BETWEEN 1 AND {MAX_ARTIFACT_BYTES}", name="size_within_limit"),
        CheckConstraint("octet_length(content) = size_bytes", name="size_matches_content"),
        CheckConstraint("sha256 = encode(sha256(content), 'hex')", name="sha256_matches_content"),
    )

    report_id: Mapped[uuid.UUID]
    format: Mapped[str] = mapped_column(String(8))
    media_type: Mapped[str] = mapped_column(String(64))
    content: Mapped[bytes] = mapped_column(LargeBinary)
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    renderer: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ReportFinding(Base):
    __tablename__ = "report_findings"
    __table_args__ = (
        PrimaryKeyConstraint("report_id", "finding_id"),
        ForeignKeyConstraint(
            ["report_id", "scan_id"],
            ["reports.id", "reports.scan_id"],
            name="fk_report_findings_report",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["finding_id", "scan_id"],
            ["findings.id", "findings.scan_id"],
            name="fk_report_findings_finding",
            ondelete="RESTRICT",
        ),
        Index("ix_report_findings_finding_id", "finding_id"),
        CheckConstraint(
            "status_at_report IN ('open', 'confirmed', 'false_positive', 'accepted_risk')",
            name="status_at_report_valid",
        ),
    )

    report_id: Mapped[uuid.UUID]
    scan_id: Mapped[uuid.UUID]
    finding_id: Mapped[uuid.UUID]
    status_at_report: Mapped[str] = mapped_column(String(32))


class ReportEvidence(Base):
    __tablename__ = "report_evidence"
    __table_args__ = (
        PrimaryKeyConstraint("report_id", "evidence_id"),
        ForeignKeyConstraint(
            ["report_id", "scan_id"],
            ["reports.id", "reports.scan_id"],
            name="fk_report_evidence_report",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "scan_id"],
            ["evidence.id", "evidence.scan_id"],
            name="fk_report_evidence_evidence",
            ondelete="RESTRICT",
        ),
    )

    report_id: Mapped[uuid.UUID]
    scan_id: Mapped[uuid.UUID]
    evidence_id: Mapped[uuid.UUID]
