"""Phase 7 retest reports (ADR 0012).

- retest_reports: a report of exactly one completed comparison. Its snapshot
  (everything the report shows) is frozen when it is requested; rendering is a
  pure function of that snapshot. Composite foreign keys tie it to the
  comparison's own baseline and current scans, both of one target.
- retest_report_artifacts: the rendered JSON / HTML / PDF bytes, hashed, at most
  25 MB each, written once by the worker that generated the report.
- retest_report_evidence: every evidence record the report shows, bound to the
  report's baseline or current scan (exactly one), so cited evidence can never
  be removed or swapped for another scan's.

Separate from the Phase 5 report tables, which are unchanged. Triggers (see the
migration) make all three tables immutable once written and require the
comparison to be completed.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    Sequence,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum_column
from app.models.enums import ReportClassification, ReportKind, ReportStatus

MAX_ARTIFACT_BYTES = 25 * 1024 * 1024

# Human-facing numbers (SV-RT-000042), separate from Phase 5's SV-R- numbers.
retest_report_number_seq = Sequence("retest_report_number_seq", metadata=Base.metadata)

_SHA256 = "~ '^[0-9a-f]{64}$'"


class RetestReport(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "retest_reports"
    __table_args__ = (
        UniqueConstraint("number"),
        UniqueConstraint("id", "baseline_scan_id"),  # baseline evidence links
        UniqueConstraint("id", "current_scan_id"),  # current evidence links
        ForeignKeyConstraint(
            ["comparison_id", "baseline_scan_id", "current_scan_id"],
            ["comparisons.id", "comparisons.baseline_scan_id", "comparisons.current_scan_id"],
            name="fk_retest_reports_comparison",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["baseline_scan_id", "baseline_assessment_id", "target_id"],
            ["scans.id", "scans.assessment_id", "scans.target_id"],
            name="fk_retest_reports_baseline_scan",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["current_scan_id", "current_assessment_id", "target_id"],
            ["scans.id", "scans.assessment_id", "scans.target_id"],
            name="fk_retest_reports_current_scan",
            ondelete="RESTRICT",
        ),
        Index(
            "ix_retest_reports_current_assessment_id_created_at",
            "current_assessment_id",
            "created_at",
        ),
        Index("ix_retest_reports_status_created_at", "status", "created_at"),
        # Idempotency: an identical request (same comparison, kind and content)
        # returns the existing report unless that one failed.
        Index(
            "uq_retest_reports_identical_content",
            "comparison_id",
            "kind",
            "content_sha256",
            unique=True,
            postgresql_where=text("status <> 'failed'"),
        ),
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
        CheckConstraint("baseline_scan_id <> current_scan_id", name="distinct_scans"),
    )

    number: Mapped[int] = mapped_column(Integer)
    comparison_id: Mapped[uuid.UUID]
    target_id: Mapped[uuid.UUID]
    baseline_assessment_id: Mapped[uuid.UUID]
    baseline_scan_id: Mapped[uuid.UUID]
    current_assessment_id: Mapped[uuid.UUID]
    current_scan_id: Mapped[uuid.UUID]
    kind: Mapped[ReportKind] = mapped_column(str_enum_column(ReportKind, "report_kind"))
    status: Mapped[ReportStatus] = mapped_column(
        str_enum_column(ReportStatus, "report_status"),
        default=ReportStatus.QUEUED,
        server_default=ReportStatus.QUEUED.value,
    )
    title: Mapped[str] = mapped_column(String(200))
    prepared_by: Mapped[str] = mapped_column(String(200))
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


class RetestReportArtifact(Base):
    __tablename__ = "retest_report_artifacts"
    __table_args__ = (
        PrimaryKeyConstraint("report_id", "format"),
        ForeignKeyConstraint(
            ["report_id"],
            ["retest_reports.id"],
            name="fk_retest_report_artifacts_report",
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


class RetestReportEvidence(Base):
    """One cited evidence record, bound to exactly one of the report's scans:
    the pair of composite foreign keys for the populated role is enforced."""

    __tablename__ = "retest_report_evidence"
    __table_args__ = (
        PrimaryKeyConstraint("report_id", "role", "evidence_id"),
        ForeignKeyConstraint(
            ["report_id", "baseline_scan_id"],
            ["retest_reports.id", "retest_reports.baseline_scan_id"],
            name="fk_retest_report_evidence_baseline_report",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "baseline_scan_id"],
            ["evidence.id", "evidence.scan_id"],
            name="fk_retest_report_evidence_baseline_evidence",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["report_id", "current_scan_id"],
            ["retest_reports.id", "retest_reports.current_scan_id"],
            name="fk_retest_report_evidence_current_report",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "current_scan_id"],
            ["evidence.id", "evidence.scan_id"],
            name="fk_retest_report_evidence_current_evidence",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "(role = 'baseline' AND baseline_scan_id IS NOT NULL AND current_scan_id IS NULL) "
            "OR (role = 'current' AND current_scan_id IS NOT NULL AND baseline_scan_id IS NULL)",
            name="exactly_one_scan_role",
        ),
    )

    report_id: Mapped[uuid.UUID]
    role: Mapped[str] = mapped_column(String(16))
    evidence_id: Mapped[uuid.UUID]
    baseline_scan_id: Mapped[uuid.UUID | None]
    current_scan_id: Mapped[uuid.UUID | None]
