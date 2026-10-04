import uuid
from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import Field, StringConstraints, model_validator

from app.models.enums import STATUSES_REQUIRING_REASON, AnalysisStatus, FindingStatus
from app.schemas.common import InputModel, NameStr, ReadModel

SeverityLiteral = Literal["critical", "high", "medium", "low", "informational"]
ConfidenceLiteral = Literal["high", "medium", "low"]
DetectionTypeLiteral = Literal["automated_detection", "manual_verification_required"]
CategoryLiteral = Literal["transport", "headers", "cookies", "disclosure", "cors", "http_methods"]
RuleIdStr = Annotated[str, StringConstraints(pattern=r"^SV-[A-Z]{3}-\d{3}$")]
ReasonStr = Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)]


class FindingRead(ReadModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    assessment_id: uuid.UUID
    target_id: uuid.UUID
    analysis_run_id: uuid.UUID
    rule_id: str
    rule_version: int
    title: str = Field(description="From the stored metadata of this exact rule version.")
    origin: str
    category: str
    severity: str
    confidence: str
    detection_type: str
    subject_type: str
    subject_key: str
    discriminator: str
    asset_id: uuid.UUID | None
    endpoint_id: uuid.UUID | None
    fingerprint: str
    details: dict[str, Any]
    affected_count: int
    status: FindingStatus
    status_reason: str | None
    status_changed_at: datetime | None
    status_changed_by: str | None
    created_at: datetime
    updated_at: datetime


class FindingDetail(FindingRead):
    rule: dict[str, Any] = Field(
        description="Metadata of the rule version that produced the finding: description, "
        "what it proves and does not prove, remediation and verified taxonomy mappings."
    )
    evidence_ids: list[uuid.UUID]


class FindingTriage(InputModel):
    status: FindingStatus
    reason: ReasonStr | None = None
    triaged_by: NameStr

    @model_validator(mode="after")
    def _reason_when_required(self) -> Self:
        if self.status in STATUSES_REQUIRING_REASON and not self.reason:
            raise ValueError(f"a reason is required for status '{self.status.value}'")
        return self


class FindingStatusChangeRead(ReadModel):
    id: uuid.UUID
    from_status: str
    to_status: str
    reason: str | None
    changed_by: str
    changed_at: datetime


class FindingSummary(ReadModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_confidence: dict[str, int]
    by_detection_type: dict[str, int]
    by_category: dict[str, int]


class AnalysisRunRead(ReadModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    ruleset_version: str
    status: AnalysisStatus
    coverage_notes: list[str]
    rule_errors: list[dict[str, str]]
    rules_evaluated: int
    findings_count: int
    error_code: str | None
    created_at: datetime
    finished_at: datetime | None


class RuleCatalog(ReadModel):
    ruleset_version: str
    rules: list[dict[str, Any]]
