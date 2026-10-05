import uuid
from datetime import datetime
from typing import Annotated, Self

from pydantic import Field, StringConstraints, field_validator, model_validator

from app.models.enums import ReportClassification, ReportFormat, ReportKind, ReportStatus
from app.schemas.common import InputModel, NameStr, ReadModel

NoteStr = Annotated[str, StringConstraints(max_length=4000)]
TemplateRef = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,63}@[0-9]{1,4}$")]


class ReportCreate(InputModel):
    scan_id: uuid.UUID = Field(description="A completed, analysed scan of this assessment.")
    kind: ReportKind = Field(
        default=ReportKind.DRAFT,
        description="final requires the assessment to be completed.",
    )
    formats: list[ReportFormat] = Field(
        default_factory=lambda: [ReportFormat.JSON, ReportFormat.HTML, ReportFormat.PDF],
        min_length=1,
        max_length=3,
        description="Must include json (the machine-readable record of every report).",
    )
    title: NameStr
    # No prepared_by: the report is prepared by the authenticated user who
    # requests it (Phase 9 M5); a body naming someone is refused.
    reviewed_by: NameStr | None = None
    classification: ReportClassification = ReportClassification.CONFIDENTIAL
    template: TemplateRef = "sv-standard@1"
    executive_summary_note: NoteStr | None = None
    scope_note: NoteStr | None = None

    @field_validator("formats")
    @classmethod
    def _formats(cls, value: list[ReportFormat]) -> list[ReportFormat]:
        if len(set(value)) != len(value):
            raise ValueError("formats must not repeat")
        if ReportFormat.JSON not in value:
            raise ValueError("formats must include json")
        return sorted(value, key=list(ReportFormat).index)

    @model_validator(mode="after")
    def _notes_not_blank(self) -> Self:
        for name in ("executive_summary_note", "scope_note"):
            value = getattr(self, name)
            if value is not None and not value.strip():
                setattr(self, name, None)
        return self


class ArtifactRead(ReadModel):
    format: str
    media_type: str
    size_bytes: int
    sha256: str
    renderer: str
    created_at: datetime


class ReportRead(ReadModel):
    id: uuid.UUID
    number: str = Field(description="Display number, e.g. SV-R-000042.")
    assessment_id: uuid.UUID
    target_id: uuid.UUID
    scan_id: uuid.UUID
    analysis_run_id: uuid.UUID
    kind: ReportKind
    status: ReportStatus
    title: str
    prepared_by: str
    requested_by_user_id: uuid.UUID | None = Field(
        description="The user who requested the report; null before Phase 9 M5."
    )
    reviewed_by: str | None
    classification: ReportClassification
    formats: list[str]
    template_id: str
    template_version: int
    template_hash: str
    schema_version: str
    snapshot_sha256: str
    content_sha256: str = Field(
        description="Digest of the content without report identity and request time: "
        "equal for reports of the same data."
    )
    error_code: str | None
    created_at: datetime
    finished_at: datetime | None
    artifacts: list[ArtifactRead] = Field(default_factory=list)


class ReportTemplateRead(ReadModel):
    id: str
    version: int
    title: str
    description: str
    sha256: str
