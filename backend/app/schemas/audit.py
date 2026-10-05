import uuid
from datetime import datetime
from typing import Any

from pydantic import Field

from app.core.audit import AuditAction
from app.models.enums import AuditActorType, AuditOutcome
from app.schemas.common import ReadModel


class ProjectAuditEventRead(ReadModel):
    """An audit event as a project owner sees it."""

    id: uuid.UUID
    occurred_at: datetime
    request_id: uuid.UUID | None
    actor_type: AuditActorType
    actor_user_id: uuid.UUID | None
    actor_label: str | None = Field(
        description="The actor's display name or username at the time, or the worker / "
        "command; descriptive only (actor_user_id identifies users)."
    )
    action: AuditAction
    outcome: AuditOutcome
    project_id: uuid.UUID | None
    resource_type: str | None
    resource_id: uuid.UUID | None
    metadata: dict[str, Any] = Field(validation_alias="metadata_")


class AuditEventRead(ProjectAuditEventRead):
    """An audit event as a global audit reader sees it (with the session row
    id of a human action; never a token)."""

    session_id: uuid.UUID | None
