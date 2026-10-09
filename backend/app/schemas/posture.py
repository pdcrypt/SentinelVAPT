"""The security posture dashboard (ADR 0015). Counts of persisted facts only:
no score, no rating, nothing derived beyond the definitions in the ADR."""

import uuid
from datetime import datetime

from pydantic import Field

from app.models.enums import ProjectRole, ReportKind, ScanStatus
from app.schemas.common import ReadModel


class FindingCounts(ReadModel):
    """Findings of the latest analysed scan of each target, summed."""

    total: int
    active: int = Field(description="Triage status is not false_positive (as in reports).")
    open: int = Field(description="Triage status is exactly 'open'.")
    by_severity: dict[str, int] = Field(
        description="Active findings by severity, in analysis order (critical … informational)."
    )
    by_status: dict[str, int] = Field(
        description="All findings by stored triage status (open, confirmed, accepted_risk, "
        "false_positive)."
    )


class ScanRef(ReadModel):
    scan_id: uuid.UUID
    assessment_id: uuid.UUID
    assessment_name: str
    finished_at: datetime


class TargetPosture(ReadModel):
    target_id: uuid.UUID
    target_name: str
    latest_scan: ScanRef | None = Field(
        description="The latest completed scan with a completed analysis; null if none."
    )
    findings: FindingCounts


class ComparisonSummary(ReadModel):
    comparison_id: uuid.UUID
    target_id: uuid.UUID
    target_name: str
    baseline_scan_id: uuid.UUID
    current_scan_id: uuid.UUID
    current_assessment_id: uuid.UUID
    finished_at: datetime
    by_state: dict[str, int] = Field(
        description="Persisted comparison records by cmp-1 state; all eight states listed."
    )


class ReportRef(ReadModel):
    report_id: uuid.UUID
    number: int
    kind: ReportKind
    title: str
    finished_at: datetime


class RecentScan(ReadModel):
    scan_id: uuid.UUID
    assessment_id: uuid.UUID
    assessment_name: str
    target_id: uuid.UUID
    target_name: str
    status: ScanStatus
    created_at: datetime
    finished_at: datetime | None
    analysed: bool
    findings_total: int | None = Field(description="Null unless the analysis completed.")


class ProjectPostureRead(ReadModel):
    project_id: uuid.UUID
    project_name: str
    role: ProjectRole = Field(description="The caller's own role in the project.")
    findings: FindingCounts
    targets: list[TargetPosture]
    targets_truncated: bool = Field(description="True if the project has more than 100 targets.")
    latest_comparison: ComparisonSummary | None
    latest_report: ReportRef | None
    latest_retest_report: ReportRef | None
    recent_scans: list[RecentScan] = Field(description="At most 10, newest first.")


class ProjectPostureSummary(ReadModel):
    project_id: uuid.UUID
    project_name: str
    role: ProjectRole
    findings: FindingCounts
    targets_with_analysed_scan: int
    latest_scan_finished_at: datetime | None
    latest_comparison: ComparisonSummary | None
    latest_report: ReportRef | None
    latest_retest_report: ReportRef | None
