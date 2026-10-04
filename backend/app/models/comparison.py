"""Phase 6 retest comparisons (ADR 0011).

- comparisons: one comparison of a retest's scan against the baseline scan its
  retest assessment pinned, under one policy version. Composite foreign keys
  require both scans to belong to one target, the current assessment to be a
  retest of the baseline assessment with exactly that baseline scan, both runs
  to belong to their scans, and the previous comparison in the chain to have
  this comparison's baseline scan as its current scan.
- comparison_records: one record per fingerprint present in either scan. Its
  findings are tied to the record's scans and fingerprint by composite keys.
- comparison_coverage_evidence: the current-scan evidence proving a subject
  was examined (FIXED / DISMISSED records), at most 25 per record.

Comparison state is separate from finding triage: nothing here changes a
finding, its history or any report. Triggers make all three tables immutable
once a comparison completes, and nothing is ever deleted.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    PrimaryKeyConstraint,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum_column
from app.models.enums import ComparisonState, ComparisonStatus

MAX_COVERAGE_EVIDENCE = 25

COMPARISON_REASONS = (
    "first_observed",
    "previously_fixed",
    "previously_dismissed",
    "previously_not_retested",
    "previously_not_comparable",
    "previously_observed",
    "rule_version_changed",
    "severity_changed",
    "confidence_changed",
    "detection_type_changed",
    "details_changed",
    "baseline_false_positive",
    "examined_condition_absent",
    "subject_not_observed",
    "out_of_scope",
    "rule_not_evaluated",
    "rule_error",
    "coverage_unavailable",
    "partial_scan",
    "tls_trust_not_evaluated",
    "observations_truncated",
)
_REASONS_ARRAY = "ARRAY[" + ", ".join(f"'{r}'" for r in COMPARISON_REASONS) + "]::varchar[]"
_TRIAGE = "('open', 'confirmed', 'false_positive', 'accepted_risk')"


class Comparison(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "comparisons"
    __table_args__ = (
        UniqueConstraint("current_scan_id", "policy_version"),  # one per scan and policy
        UniqueConstraint("id", "baseline_scan_id", "current_scan_id"),  # records' key
        UniqueConstraint("id", "current_scan_id"),  # chain link target
        ForeignKeyConstraint(
            ["baseline_scan_id", "baseline_assessment_id", "target_id"],
            ["scans.id", "scans.assessment_id", "scans.target_id"],
            name="fk_comparisons_baseline_scan",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["current_scan_id", "current_assessment_id", "target_id"],
            ["scans.id", "scans.assessment_id", "scans.target_id"],
            name="fk_comparisons_current_scan",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["current_assessment_id", "baseline_assessment_id", "baseline_scan_id"],
            [
                "assessments.id",
                "assessments.retest_of_assessment_id",
                "assessments.baseline_scan_id",
            ],
            name="fk_comparisons_retest",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["baseline_run_id", "baseline_scan_id"],
            ["analysis_runs.id", "analysis_runs.scan_id"],
            name="fk_comparisons_baseline_run",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["current_run_id", "current_scan_id"],
            ["analysis_runs.id", "analysis_runs.scan_id"],
            name="fk_comparisons_current_run",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["previous_comparison_id", "baseline_scan_id"],
            ["comparisons.id", "comparisons.current_scan_id"],
            name="fk_comparisons_previous",
            ondelete="RESTRICT",
        ),
        Index("ix_comparisons_status_created_at", "status", "created_at"),
        Index("ix_comparisons_current_assessment_id", "current_assessment_id"),
        CheckConstraint("baseline_scan_id <> current_scan_id", name="distinct_scans"),
        CheckConstraint("policy_version ~ '^cmp-[0-9]{1,4}$'", name="policy_version_format"),
        CheckConstraint(
            "(status IN ('completed', 'failed')) = (finished_at IS NOT NULL)",
            name="finished_iff_terminal",
        ),
        CheckConstraint("(status = 'failed') = (error_code IS NOT NULL)", name="error_iff_failed"),
        CheckConstraint(
            "(status = 'completed') = (summary IS NOT NULL)", name="summary_iff_completed"
        ),
    )

    target_id: Mapped[uuid.UUID]
    baseline_assessment_id: Mapped[uuid.UUID]
    baseline_scan_id: Mapped[uuid.UUID]
    baseline_run_id: Mapped[uuid.UUID]
    current_assessment_id: Mapped[uuid.UUID]
    current_scan_id: Mapped[uuid.UUID]
    current_run_id: Mapped[uuid.UUID]
    previous_comparison_id: Mapped[uuid.UUID | None]
    policy_version: Mapped[str] = mapped_column(String(16))
    status: Mapped[ComparisonStatus] = mapped_column(
        str_enum_column(ComparisonStatus, "comparison_status"),
        default=ComparisonStatus.QUEUED,
        server_default=ComparisonStatus.QUEUED.value,
    )
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error_code: Mapped[str | None] = mapped_column(String(64))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ComparisonRecord(Base):
    __tablename__ = "comparison_records"
    __table_args__ = (
        PrimaryKeyConstraint("comparison_id", "fingerprint"),
        UniqueConstraint("comparison_id", "fingerprint", "current_scan_id"),  # evidence key
        ForeignKeyConstraint(
            ["comparison_id", "baseline_scan_id", "current_scan_id"],
            [
                "comparisons.id",
                "comparisons.baseline_scan_id",
                "comparisons.current_scan_id",
            ],
            name="fk_comparison_records_comparison",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["baseline_finding_id", "baseline_scan_id", "fingerprint"],
            ["findings.id", "findings.scan_id", "findings.fingerprint"],
            name="fk_comparison_records_baseline_finding",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["current_finding_id", "current_scan_id", "fingerprint"],
            ["findings.id", "findings.scan_id", "findings.fingerprint"],
            name="fk_comparison_records_current_finding",
            ondelete="RESTRICT",
        ),
        Index("ix_comparison_records_comparison_id_state", "comparison_id", "state"),
        CheckConstraint("fingerprint ~ '^[0-9a-f]{64}$'", name="fingerprint_hex"),
        CheckConstraint(
            "baseline_finding_id IS NOT NULL OR current_finding_id IS NOT NULL",
            name="some_finding",
        ),
        CheckConstraint(
            "state NOT IN ('new', 'reopened') "
            "OR (baseline_finding_id IS NULL AND current_finding_id IS NOT NULL)",
            name="new_has_only_current",
        ),
        CheckConstraint(
            "state NOT IN ('unchanged', 'still_open') "
            "OR (baseline_finding_id IS NOT NULL AND current_finding_id IS NOT NULL)",
            name="present_has_both",
        ),
        CheckConstraint(
            "state NOT IN ('fixed', 'dismissed', 'not_retested', 'not_comparable') "
            "OR (baseline_finding_id IS NOT NULL AND current_finding_id IS NULL)",
            name="absent_has_only_baseline",
        ),
        CheckConstraint(
            "state <> 'fixed' OR baseline_triage <> 'false_positive'",
            name="false_positive_never_fixed",
        ),
        CheckConstraint(
            "state <> 'dismissed' OR baseline_triage = 'false_positive'",
            name="dismissed_requires_false_positive",
        ),
        CheckConstraint(
            "(baseline_finding_id IS NULL) = (baseline_triage IS NULL)",
            name="baseline_triage_iff_baseline",
        ),
        CheckConstraint(
            "(current_finding_id IS NULL) = (current_triage IS NULL)",
            name="current_triage_iff_current",
        ),
        CheckConstraint(
            f"baseline_triage IS NULL OR baseline_triage IN {_TRIAGE}",
            name="baseline_triage_values",
        ),
        CheckConstraint(
            f"current_triage IS NULL OR current_triage IN {_TRIAGE}",
            name="current_triage_values",
        ),
        CheckConstraint(
            f"cardinality(reasons) <= 10 AND reasons <@ {_REASONS_ARRAY}",
            name="reasons_valid",
        ),
    )

    comparison_id: Mapped[uuid.UUID]
    fingerprint: Mapped[str] = mapped_column(String(64))
    baseline_scan_id: Mapped[uuid.UUID]
    current_scan_id: Mapped[uuid.UUID]
    rule_id: Mapped[str] = mapped_column(String(32))
    state: Mapped[ComparisonState] = mapped_column(
        str_enum_column(ComparisonState, "comparison_state")
    )
    reasons: Mapped[list[str]] = mapped_column(ARRAY(String(64)))
    baseline_finding_id: Mapped[uuid.UUID | None]
    current_finding_id: Mapped[uuid.UUID | None]
    baseline_triage: Mapped[str | None] = mapped_column(String(32))
    current_triage: Mapped[str | None] = mapped_column(String(32))


class ComparisonCoverageEvidence(Base):
    __tablename__ = "comparison_coverage_evidence"
    __table_args__ = (
        PrimaryKeyConstraint("comparison_id", "fingerprint", "evidence_id"),
        ForeignKeyConstraint(
            ["comparison_id", "fingerprint", "current_scan_id"],
            [
                "comparison_records.comparison_id",
                "comparison_records.fingerprint",
                "comparison_records.current_scan_id",
            ],
            name="fk_comparison_coverage_evidence_record",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "current_scan_id"],
            ["evidence.id", "evidence.scan_id"],
            name="fk_comparison_coverage_evidence_evidence",
            ondelete="RESTRICT",
        ),
    )

    comparison_id: Mapped[uuid.UUID]
    fingerprint: Mapped[str] = mapped_column(String(64))
    current_scan_id: Mapped[uuid.UUID]
    evidence_id: Mapped[uuid.UUID]
