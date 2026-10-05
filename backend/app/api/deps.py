"""Dependency wiring: builds services from a request-scoped session."""

import uuid
from typing import Annotated

from fastapi import Depends, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.clock import Clock, utc_now
from app.core.config import Settings
from app.core.passwords import Argon2Parameters, Passwords
from app.db.session import get_session
from app.repositories import (
    AnalysisRepository,
    AssessmentRepository,
    ComparisonRepository,
    ProjectRepository,
    ReportRepository,
    RetestReportRepository,
    ScanRepository,
    ScanResultRepository,
    TargetAuthorizationRepository,
    TargetRepository,
)
from app.services.assessments import AssessmentService
from app.services.audit import INTERNAL, AuditContext, AuditService
from app.services.auth import AuthService, Principal
from app.services.comparisons import ComparisonService
from app.services.findings import FindingService
from app.services.projects import ProjectService
from app.services.reports import ReportService
from app.services.retest_reports import RetestReportService
from app.services.retests import RetestService
from app.services.scans import ScanService
from app.services.targets import TargetService

SessionDep = Annotated[Session, Depends(get_session)]


def get_clock() -> Clock:
    return utc_now


ClockDep = Annotated[Clock, Depends(get_clock)]


def get_app_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


SettingsDep = Annotated[Settings, Depends(get_app_settings)]


def get_passwords(settings: SettingsDep) -> Passwords:
    return Passwords(
        Argon2Parameters(
            time_cost=settings.auth_argon2_time_cost,
            memory_kib=settings.auth_argon2_memory_kib,
            parallelism=settings.auth_argon2_parallelism,
        )
    )


def get_auth_service(
    session: SessionDep,
    settings: SettingsDep,
    clock: ClockDep,
    passwords: Annotated[Passwords, Depends(get_passwords)],
) -> AuthService:
    return AuthService(session, settings, clock, passwords)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


def get_audit_context(request: Request) -> AuditContext:
    """Request ID (X-Request-ID, only if it is a UUID) and source address (the
    direct peer; M8 adds trusted forwarding from the Next.js server)."""
    raw = request.headers.get("x-request-id", "")
    try:
        request_id: uuid.UUID | None = uuid.UUID(raw) if raw else None
    except ValueError:
        request_id = None
    source = request.client.host if request.client else "unknown"
    return AuditContext(request_id=request_id, source=source[:64])


AuditContextDep = Annotated[AuditContext, Depends(get_audit_context)]

# Only the Authorization header is ever read: FastAPI never accepts cookies
# (or query parameters) as credentials (ADR 0014).
_bearer = HTTPBearer(auto_error=False, description="Opaque session token from POST /auth/login")


def get_principal(
    auth: AuthServiceDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    context: AuditContextDep,
) -> Principal:
    """The authenticated platform user. In M2 only the /auth endpoints use it;
    M3/M4 attach it (with project authorization) to every route."""
    token = credentials.credentials if credentials is not None else None
    return auth.authenticate(token, context)


PrincipalDep = Annotated[Principal, Depends(get_principal)]


def get_project_service(session: SessionDep, context: AuditContextDep = INTERNAL) -> ProjectService:
    return ProjectService(
        ProjectRepository(session),
        session,
        audit=AuditService(session, context),
    )


def get_target_service(
    session: SessionDep, clock: ClockDep, context: AuditContextDep = INTERNAL
) -> TargetService:
    return TargetService(
        TargetRepository(session),
        TargetAuthorizationRepository(session),
        ProjectRepository(session),
        session,
        clock,
        audit=AuditService(session, context),
    )


def get_assessment_service(
    session: SessionDep, clock: ClockDep, context: AuditContextDep = INTERNAL
) -> AssessmentService:
    return AssessmentService(
        AssessmentRepository(session),
        TargetRepository(session),
        ProjectRepository(session),
        session,
        clock,
        scans=ScanRepository(session),
        audit=AuditService(session, context),
    )


def get_scan_service(
    session: SessionDep, clock: ClockDep, context: AuditContextDep = INTERNAL
) -> ScanService:
    return ScanService(
        ScanRepository(session),
        ScanResultRepository(session),
        AssessmentRepository(session),
        TargetRepository(session),
        session,
        clock,
        audit=AuditService(session, context),
    )


def get_finding_service(
    session: SessionDep, clock: ClockDep, context: AuditContextDep = INTERNAL
) -> FindingService:
    return FindingService(
        AnalysisRepository(session),
        ScanRepository(session),
        AssessmentRepository(session),
        session,
        clock,
        audit=AuditService(session, context),
    )


def get_report_service(
    session: SessionDep, clock: ClockDep, context: AuditContextDep = INTERNAL
) -> ReportService:
    return ReportService(
        ReportRepository(session),
        ScanRepository(session),
        AssessmentRepository(session),
        session,
        session,
        clock,
        audit=AuditService(session, context),
    )


def get_retest_service(
    session: SessionDep, clock: ClockDep, context: AuditContextDep = INTERNAL
) -> RetestService:
    return RetestService(
        AssessmentRepository(session),
        TargetRepository(session),
        ScanRepository(session),
        ComparisonRepository(session),
        session,
        clock,
        audit=AuditService(session, context),
    )


def get_comparison_service(
    session: SessionDep, context: AuditContextDep = INTERNAL
) -> ComparisonService:
    return ComparisonService(
        ComparisonRepository(session),
        AssessmentRepository(session),
        ScanRepository(session),
        session,
        audit=AuditService(session, context),
    )


def get_retest_report_service(
    session: SessionDep, clock: ClockDep, context: AuditContextDep = INTERNAL
) -> RetestReportService:
    return RetestReportService(
        RetestReportRepository(session),
        AssessmentRepository(session),
        session,
        session,
        clock,
        audit=AuditService(session, context),
    )


ProjectServiceDep = Annotated[ProjectService, Depends(get_project_service)]
TargetServiceDep = Annotated[TargetService, Depends(get_target_service)]
AssessmentServiceDep = Annotated[AssessmentService, Depends(get_assessment_service)]
ScanServiceDep = Annotated[ScanService, Depends(get_scan_service)]
FindingServiceDep = Annotated[FindingService, Depends(get_finding_service)]
ReportServiceDep = Annotated[ReportService, Depends(get_report_service)]
RetestServiceDep = Annotated[RetestService, Depends(get_retest_service)]
ComparisonServiceDep = Annotated[ComparisonService, Depends(get_comparison_service)]
RetestReportServiceDep = Annotated[RetestReportService, Depends(get_retest_report_service)]

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]
