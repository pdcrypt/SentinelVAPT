import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import Field, StringConstraints

from app.models.enums import AssessmentStatus, ComparisonState, ComparisonStatus
from app.schemas.common import DescriptionStr, InputModel, NameStr, ReadModel

FingerprintStr = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class RetestCreate(InputModel):
    name: NameStr
    description: DescriptionStr | None = None
    baseline_scan_id: uuid.UUID | None = Field(
        default=None,
        description="A completed, analysed scan of the parent assessment. Default: the most "
        "recently finished one.",
    )


class LineageComparison(ReadModel):
    id: uuid.UUID
    current_scan_id: uuid.UUID
    status: ComparisonStatus
    policy_version: str


class LineageEntry(ReadModel):
    position: int = Field(description="0 is the original assessment.")
    assessment_id: uuid.UUID
    name: str
    status: AssessmentStatus
    authorization_id: uuid.UUID
    retest_of_assessment_id: uuid.UUID | None
    baseline_scan_id: uuid.UUID | None
    comparisons: list[LineageComparison]


class ComparisonCreate(InputModel):
    scan_id: uuid.UUID = Field(description="A completed, analysed scan of this retest.")


class ComparisonRead(ReadModel):
    id: uuid.UUID
    target_id: uuid.UUID
    baseline_assessment_id: uuid.UUID
    baseline_scan_id: uuid.UUID
    baseline_run_id: uuid.UUID
    current_assessment_id: uuid.UUID
    current_scan_id: uuid.UUID
    current_run_id: uuid.UUID
    previous_comparison_id: uuid.UUID | None
    policy_version: str
    status: ComparisonStatus
    summary: dict[str, Any] | None
    error_code: str | None
    created_at: datetime
    finished_at: datetime | None


class ComparisonRecordRead(ReadModel):
    fingerprint: str
    rule_id: str
    state: ComparisonState
    reasons: list[str]
    baseline_finding_id: uuid.UUID | None
    baseline_triage: str | None = Field(description="Triage status when compared.")
    baseline_evidence_ids: list[uuid.UUID]
    current_finding_id: uuid.UUID | None
    current_triage: str | None = Field(description="Triage status when compared.")
    current_evidence_ids: list[uuid.UUID]
    coverage_evidence_ids: list[uuid.UUID] = Field(
        description="Current-scan evidence proving the subject was examined (fixed/dismissed)."
    )
