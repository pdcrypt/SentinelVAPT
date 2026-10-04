"""Phase 4 analysis results (ADR 0009).

- analysis_runs: one analysis of one scan per ruleset version.
- rule_versions: immutable snapshot of each rule version's metadata, so old
  findings keep the exact text and mappings that produced them.
- findings: one evaluation result. Identity is `fingerprint` (stable across
  scans and rule versions); `rule_version` records which logic produced it.
- finding_evidence: references to existing evidence (never copied), in the
  same scan.
- finding_status_changes: append-only triage history.
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
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum_column
from app.models.enums import AnalysisStatus, FindingStatus


class AnalysisRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "analysis_runs"
    __table_args__ = (
        UniqueConstraint("scan_id", "ruleset_version"),
        UniqueConstraint("id", "scan_id"),  # target of reports' composite foreign key
        Index("ix_analysis_runs_status_created_at", "status", "created_at"),
        CheckConstraint(
            "(status IN ('completed', 'failed')) = (finished_at IS NOT NULL)",
            name="finished_iff_terminal",
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"))
    ruleset_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[AnalysisStatus] = mapped_column(
        str_enum_column(AnalysisStatus, "analysis_status"),
        default=AnalysisStatus.QUEUED,
        server_default=AnalysisStatus.QUEUED.value,
    )
    coverage_notes: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]")
    rule_errors: Mapped[list[dict[str, str]]] = mapped_column(
        JSONB, default=list, server_default="[]"
    )
    rules_evaluated: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    findings_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    error_code: Mapped[str | None] = mapped_column(String(64))
    # Rule versions this run evaluated, [{"rule_id", "version"}] (ADR 0011).
    # Null for runs recorded before Phase 6.
    rule_versions: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RuleVersion(Base):
    """Insert-once. A database trigger rejects UPDATE and DELETE."""

    __tablename__ = "rule_versions"
    __table_args__ = (
        PrimaryKeyConstraint("rule_id", "version"),
        CheckConstraint("version >= 1", name="version_positive"),
    )

    rule_id: Mapped[str] = mapped_column(String(32))
    version: Mapped[int] = mapped_column(Integer)
    metadata_hash: Mapped[str] = mapped_column(String(64))
    rule_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint"),
        UniqueConstraint("id", "scan_id"),  # target of finding_evidence's composite key
        # Target of comparison records' keys: a record's finding must be of the
        # record's scan and carry the record's fingerprint.
        UniqueConstraint("id", "scan_id", "fingerprint"),
        ForeignKeyConstraint(
            ["scan_id", "assessment_id", "target_id"],
            ["scans.id", "scans.assessment_id", "scans.target_id"],
            name="fk_findings_scan",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["rule_id", "rule_version"],
            ["rule_versions.rule_id", "rule_versions.version"],
            name="fk_findings_rule_version",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["asset_id", "scan_id"],
            ["assets.id", "assets.scan_id"],
            name="fk_findings_asset",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["endpoint_id", "scan_id"],
            ["endpoints.id", "endpoints.scan_id"],
            name="fk_findings_endpoint",
            ondelete="RESTRICT",
        ),
        Index("ix_findings_assessment_id", "assessment_id"),
        CheckConstraint("origin = 'rule'", name="origin_rule_only"),
        CheckConstraint("affected_count >= 1", name="affected_count_positive"),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'informational')",
            name="severity_values",
        ),
        CheckConstraint("confidence IN ('high', 'medium', 'low')", name="confidence_values"),
        CheckConstraint(
            "detection_type IN ('automated_detection', 'manual_verification_required')",
            name="detection_type_values",
        ),
        CheckConstraint("subject_type IN ('origin', 'endpoint')", name="subject_type_values"),
        CheckConstraint(
            "status NOT IN ('false_positive', 'accepted_risk') "
            "OR (status_reason IS NOT NULL AND length(btrim(status_reason)) > 0)",
            name="reason_required",
        ),
    )

    scan_id: Mapped[uuid.UUID]
    assessment_id: Mapped[uuid.UUID]
    target_id: Mapped[uuid.UUID]
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT")
    )
    rule_id: Mapped[str] = mapped_column(String(32))
    rule_version: Mapped[int] = mapped_column(Integer)
    origin: Mapped[str] = mapped_column(String(16), default="rule", server_default="rule")
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    detection_type: Mapped[str] = mapped_column(String(32))
    subject_type: Mapped[str] = mapped_column(String(16))
    subject_key: Mapped[str] = mapped_column(Text)
    discriminator: Mapped[str] = mapped_column(String(255), default="", server_default="")
    asset_id: Mapped[uuid.UUID | None]
    endpoint_id: Mapped[uuid.UUID | None]
    fingerprint: Mapped[str] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB)
    affected_count: Mapped[int] = mapped_column(Integer)
    status: Mapped[FindingStatus] = mapped_column(
        str_enum_column(FindingStatus, "finding_status"),
        default=FindingStatus.OPEN,
        server_default=FindingStatus.OPEN.value,
    )
    status_reason: Mapped[str | None] = mapped_column(Text)
    status_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status_changed_by: Mapped[str | None] = mapped_column(String(200))


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    __table_args__ = (
        PrimaryKeyConstraint("finding_id", "evidence_id"),
        ForeignKeyConstraint(
            ["finding_id", "scan_id"],
            ["findings.id", "findings.scan_id"],
            name="fk_finding_evidence_finding",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "scan_id"],
            ["evidence.id", "evidence.scan_id"],
            name="fk_finding_evidence_evidence",
            ondelete="RESTRICT",
        ),
    )

    finding_id: Mapped[uuid.UUID]
    evidence_id: Mapped[uuid.UUID]
    scan_id: Mapped[uuid.UUID]


class FindingStatusChange(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "finding_status_changes"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    from_status: Mapped[str] = mapped_column(String(32))
    to_status: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str | None] = mapped_column(Text)
    changed_by: Mapped[str] = mapped_column(String(200))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
