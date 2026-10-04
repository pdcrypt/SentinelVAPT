"""Audit-event recording (ADR 0014).

Phase 9 M2 records only authentication events, which are also the record that
login throttling counts. M6 extends this service to every audited action and
adds read endpoints; callers keep using `record`.

Metadata keys are fixed by the callers (never request data) and the database
refuses secret-like keys, non-scalar values and oversized metadata.
"""

import uuid
from dataclasses import dataclass
from typing import Any

from app.models import AuditEvent
from app.models.enums import AuditActorType, AuditOutcome
from app.repositories.identity import AuditRepository


@dataclass(frozen=True)
class AuditContext:
    """Request-level facts every event of one request shares."""

    request_id: uuid.UUID | None
    source: str


class AuditRecorder:
    def __init__(self, events: AuditRepository) -> None:
        self.events = events

    def record(
        self,
        action: str,
        outcome: AuditOutcome,
        *,
        context: AuditContext,
        actor_type: AuditActorType,
        actor_user_id: uuid.UUID | None = None,
        actor_label: str | None = None,
        session_id: uuid.UUID | None = None,
        resource_type: str | None = None,
        resource_id: uuid.UUID | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.events.add(
            AuditEvent(
                request_id=context.request_id,
                actor_type=actor_type,
                actor_user_id=actor_user_id,
                actor_label=actor_label,
                session_id=session_id,
                action=action,
                outcome=outcome,
                resource_type=resource_type,
                resource_id=resource_id,
                metadata_={"source": context.source, **(metadata or {})},
            )
        )
