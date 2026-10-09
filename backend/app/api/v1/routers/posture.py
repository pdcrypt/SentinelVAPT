"""The security posture dashboard (ADR 0015): read-only counts of persisted
facts. Reading posture records no audit event."""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.api.authz import authenticated, authorize
from app.api.deps import Limit, Offset, SessionDep
from app.core.authz import AccessDecision
from app.core.authz import Permission as P
from app.core.authz import ResourceType as R
from app.core.errors import NotFoundError
from app.models import Project
from app.repositories.posture import PostureRepository
from app.schemas.posture import ProjectPostureRead, ProjectPostureSummary
from app.services.auth import Principal
from app.services.posture import PostureService

router = APIRouter(tags=["posture"])


@router.get("/posture", response_model=list[ProjectPostureSummary])
def posture_overview(
    session: SessionDep,
    principal: Annotated[Principal, Depends(authenticated())],
    limit: Limit = 50,
    offset: Offset = 0,
) -> list[dict[str, Any]]:
    """A posture summary of each project you are a member of, in the order of
    GET /projects. Projects come from your memberships only; a global role adds
    none, and there is no parameter to name a project."""
    return PostureService(PostureRepository(session)).overview(
        principal.user_id, limit=limit, offset=offset
    )


@router.get("/projects/{project_id}/posture", response_model=ProjectPostureRead)
def project_posture(
    project_id: uuid.UUID,
    session: SessionDep,
    access: Annotated[AccessDecision, Depends(authorize(P.PROJECT_READ, R.PROJECT, "project_id"))],
) -> dict[str, Any]:
    """One project's posture: current findings (latest analysed scan of each
    target), the latest retest outcome, latest reports and recent scans."""
    project = session.get(Project, project_id)
    if project is None or access.role is None:  # pragma: no cover  # resolved by the descriptor
        raise NotFoundError("project not found")
    return PostureService(PostureRepository(session)).project(project.id, project.name, access.role)
