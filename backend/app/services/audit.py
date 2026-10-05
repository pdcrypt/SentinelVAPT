"""Audit recording (ADR 0014; Phase 9 M2, extended in M6).

Every audit event is created here, by server code, from trusted context:

- the action is one of the closed vocabulary (app/core/audit.py; the
  database refuses any other through a foreign key);
- the actor is the authenticated user (a UserActor built from the Principal,
  with its session) or a named system actor (a worker id or a server
  command), never request data;
- the project of a project-scoped event is derived from the resource's own
  rows (the M3 resolver), never supplied by the caller;
- metadata is checked against the action's allowlist.

Transactions: an event is added to the caller's session and becomes durable
with the caller's commit, so a successful change and its event commit
together or not at all. A refusal that must be remembered (`denial`) rolls
the caller's unfinished work back, records the event and commits it before
the refusal is raised (as M2 does for failed logins).
"""

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.actors import UserActor, require_user_actor
from app.core.audit import (
    PLATFORM_RESOURCES,
    AuditAction,
    AuditMetadataError,
    audit_action,
    validate_metadata,
)
from app.core.authz import ResourceType
from app.core.errors import AuthenticationError
from app.models import AuditEvent
from app.models.enums import AuditActorType, AuditOutcome
from app.repositories.authz import ProjectResolver
from app.repositories.identity import AuditRepository

# Resolution needs a user id; the role it reports is not used here.
_NOBODY = uuid.UUID(int=0)


@dataclass(frozen=True)
class AuditContext:
    """Request-level facts every event of one request shares."""

    request_id: uuid.UUID | None
    source: str


INTERNAL = AuditContext(request_id=None, source="internal")
WORKER = AuditContext(request_id=None, source="worker")

Resource = tuple[ResourceType | str, uuid.UUID]


def _resource_type(value: ResourceType | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, ResourceType) or value in PLATFORM_RESOURCES:
        return str(value)
    if value in {r.value for r in ResourceType}:
        return str(value)
    raise AuditMetadataError(f"not an audit resource type: {value!r}")


class AuditRecorder:
    """Low-level insertion with vocabulary, resource-type and metadata checks.
    Authentication (M2) uses it directly; everything else goes through
    AuditService."""

    def __init__(self, events: AuditRepository) -> None:
        self.events = events

    def record(
        self,
        action: AuditAction | str,
        outcome: AuditOutcome,
        *,
        context: AuditContext,
        actor_type: AuditActorType,
        actor_user_id: uuid.UUID | None = None,
        actor_label: str | None = None,
        session_id: uuid.UUID | None = None,
        project_id: uuid.UUID | None = None,
        resource_type: ResourceType | str | None = None,
        resource_id: uuid.UUID | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> uuid.UUID:
        checked = audit_action(action)
        event = AuditEvent(
            id=uuid.uuid4(),
            request_id=context.request_id,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            actor_label=actor_label,
            session_id=session_id,
            project_id=project_id,
            action=checked.value,
            outcome=outcome,
            resource_type=_resource_type(resource_type),
            resource_id=resource_id,
            metadata_={"source": context.source, **validate_metadata(checked, metadata)},
        )
        self.events.add(event)
        return event.id


class AuditService:
    """The audit trail of one request (or one worker step), bound to its
    session."""

    def __init__(self, session: Session, context: AuditContext = INTERNAL) -> None:
        self.session = session
        self.context = context
        self.recorder = AuditRecorder(AuditRepository(session))
        self.resolver = ProjectResolver(session)

    def _project(self, resource: Resource | None) -> uuid.UUID | None:
        if resource is None or resource[0] in PLATFORM_RESOURCES:
            return None
        kind = ResourceType(resource[0])
        found = self.resolver.resolve(kind, {"id": str(resource[1])}, _NOBODY)
        if found is None:
            raise AuditMetadataError(f"audited {kind.value} {resource[1]} does not exist")
        return found.project_id

    def _active(self, actor: UserActor) -> None:
        """A disabled user acts no more: checked under a share lock, so it
        serializes with disabling the account."""
        active = self.session.execute(
            text("SELECT is_active FROM users WHERE id = :u FOR SHARE"), {"u": actor.user_id}
        ).scalar()
        if not active:
            raise AuthenticationError()

    def user(
        self,
        action: AuditAction,
        actor: UserActor,
        *,
        resource: Resource | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        metadata: dict[str, Any] | None = None,
    ) -> uuid.UUID:
        """An action of the authenticated user (with their session)."""
        actor = require_user_actor(actor)
        self._active(actor)
        return self.recorder.record(
            action,
            outcome,
            context=self.context,
            actor_type=AuditActorType.USER,
            actor_user_id=actor.user_id,
            actor_label=actor.label,
            session_id=actor.session_id,
            project_id=self._project(resource),
            resource_type=resource[0] if resource else None,
            resource_id=resource[1] if resource else None,
            metadata=metadata,
        )

    def system(
        self,
        action: AuditAction,
        performer: str,
        *,
        resource: Resource | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        metadata: dict[str, Any] | None = None,
    ) -> uuid.UUID:
        """An action of a worker or server-side command, named by `performer`
        (a worker id, never a user's id or name). No session."""
        if not performer or isinstance(performer, UserActor):
            raise AuditMetadataError("a system event names its performer")
        return self.recorder.record(
            action,
            outcome,
            context=self.context,
            actor_type=AuditActorType.SYSTEM,
            actor_label=str(performer)[:200],
            project_id=self._project(resource),
            resource_type=resource[0] if resource else None,
            resource_id=resource[1] if resource else None,
            metadata=metadata,
        )

    def denial(
        self,
        action: AuditAction,
        actor: UserActor,
        *,
        resource: Resource | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Records a refusal durably: unfinished work of the caller is rolled
        back first, then the event alone is committed. The caller raises the
        refusal afterwards."""
        self.session.rollback()
        self.user(action, actor, resource=resource, outcome=AuditOutcome.DENIED, metadata=metadata)
        self.session.commit()
