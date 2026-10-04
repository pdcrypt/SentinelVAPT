import uuid
from datetime import datetime
from typing import ClassVar

from app.models.enums import AssessmentStatus
from app.schemas.common import DescriptionStr, InputModel, NameStr, PatchModel, ReadModel


class AssessmentCreate(InputModel):
    name: NameStr
    description: DescriptionStr | None = None


class AssessmentUpdate(PatchModel):
    nullable_fields: ClassVar[frozenset[str]] = frozenset({"description"})

    name: NameStr | None = None
    description: DescriptionStr | None = None


class AssessmentRead(ReadModel):
    id: uuid.UUID
    target_id: uuid.UUID
    # The authorization record (and therefore scope) the assessment was planned under.
    authorization_id: uuid.UUID
    name: str
    description: str | None
    status: AssessmentStatus
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime
