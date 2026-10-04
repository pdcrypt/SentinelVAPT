"""Dependency wiring: builds services from a request-scoped session."""

from typing import Annotated

from fastapi import Depends, Query
from sqlalchemy.orm import Session

from app.core.clock import Clock, utc_now
from app.db.session import get_session
from app.repositories import (
    AssessmentRepository,
    ProjectRepository,
    TargetAuthorizationRepository,
    TargetRepository,
)
from app.services.assessments import AssessmentService
from app.services.projects import ProjectService
from app.services.targets import TargetService

SessionDep = Annotated[Session, Depends(get_session)]


def get_clock() -> Clock:
    return utc_now


ClockDep = Annotated[Clock, Depends(get_clock)]


def get_project_service(session: SessionDep) -> ProjectService:
    return ProjectService(ProjectRepository(session), session)


def get_target_service(session: SessionDep, clock: ClockDep) -> TargetService:
    return TargetService(
        TargetRepository(session),
        TargetAuthorizationRepository(session),
        ProjectRepository(session),
        session,
        clock,
    )


def get_assessment_service(session: SessionDep, clock: ClockDep) -> AssessmentService:
    return AssessmentService(
        AssessmentRepository(session),
        TargetRepository(session),
        ProjectRepository(session),
        session,
        clock,
    )


ProjectServiceDep = Annotated[ProjectService, Depends(get_project_service)]
TargetServiceDep = Annotated[TargetService, Depends(get_target_service)]
AssessmentServiceDep = Annotated[AssessmentService, Depends(get_assessment_service)]

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]
