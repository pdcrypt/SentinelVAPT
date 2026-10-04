import uuid
from datetime import datetime
from typing import ClassVar

from app.schemas.common import DescriptionStr, InputModel, NameStr, PatchModel, ReadModel


class ProjectCreate(InputModel):
    name: NameStr
    description: DescriptionStr | None = None


class ProjectUpdate(PatchModel):
    nullable_fields: ClassVar[frozenset[str]] = frozenset({"description"})

    name: NameStr | None = None
    description: DescriptionStr | None = None


class ProjectRead(ReadModel):
    id: uuid.UUID
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime
