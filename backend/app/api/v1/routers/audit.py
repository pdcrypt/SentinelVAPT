"""Audit reads (ADR 0014, Phase 9 M6). There is no way to write, change or
delete an audit event through the API: events are created by the server as
it acts.

- Project audit: owners of the project (audit.read_project). The query is
  always scoped to the authorized project; no filter can widen it.
- Global audit: global admins (audit.read_global). The global role grants no
  project audit (or any project) access.

Reads are not themselves audited (ADR 0014 coverage policy).
"""

import uuid
from collections.abc import Sequence
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import AwareDatetime

from app.api.authz import authorize, require_global
from app.api.deps import Limit, Offset, SessionDep
from app.core.audit import AuditAction
from app.core.authz import Permission as P
from app.core.authz import ResourceType as R
from app.models import AuditEvent
from app.models.enums import AuditActorType, AuditOutcome
from app.repositories.identity import AuditFilters, AuditRepository
from app.schemas.audit import AuditEventRead, ProjectAuditEventRead

router = APIRouter(tags=["audit"])

ResourceTypeQuery = Annotated[str | None, Query(pattern=r"^[a-z_]{1,32}$")]


def _filters(
    action: AuditAction | None = None,
    outcome: AuditOutcome | None = None,
    actor_type: AuditActorType | None = None,
    actor_user_id: uuid.UUID | None = None,
    resource_type: ResourceTypeQuery = None,
    resource_id: uuid.UUID | None = None,
    occurred_from: AwareDatetime | None = None,
    occurred_to: AwareDatetime | None = None,
) -> AuditFilters:
    return AuditFilters(
        action=action.value if action else None,
        outcome=outcome.value if outcome else None,
        actor_type=actor_type.value if actor_type else None,
        actor_user_id=actor_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        occurred_from=occurred_from,
        occurred_to=occurred_to,
    )


FiltersDep = Annotated[AuditFilters, Depends(_filters)]


@router.get(
    "/projects/{project_id}/audit-events",
    dependencies=[Depends(authorize(P.AUDIT_READ_PROJECT, R.PROJECT, "project_id"))],
    response_model=list[ProjectAuditEventRead],
)
def list_project_audit_events(
    project_id: uuid.UUID,
    session: SessionDep,
    filters: FiltersDep,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Sequence[AuditEvent]:
    """This project's security history, newest first."""
    return AuditRepository(session).list_events(
        filters, project_id=project_id, limit=limit, offset=offset
    )


@router.get(
    "/audit-events",
    dependencies=[Depends(require_global(P.AUDIT_READ_GLOBAL))],
    response_model=list[AuditEventRead],
)
def list_audit_events(
    session: SessionDep,
    filters: FiltersDep,
    project_id: uuid.UUID | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Sequence[AuditEvent]:
    """The whole platform's security history, newest first."""
    return AuditRepository(session).list_events(
        filters, project_id=project_id, limit=limit, offset=offset
    )
