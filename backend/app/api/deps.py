"""Dependency wiring: builds services from a request-scoped session."""

from typing import Annotated

from fastapi import Depends, Query
from sqlalchemy.orm import Session

from app.core.clock import Clock, utc_now
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
        scans=ScanRepository(session),
    )


def get_scan_service(session: SessionDep, clock: ClockDep) -> ScanService:
    return ScanService(
        ScanRepository(session),
        ScanResultRepository(session),
        AssessmentRepository(session),
        TargetRepository(session),
        session,
        clock,
    )


def get_finding_service(session: SessionDep, clock: ClockDep) -> FindingService:
    return FindingService(
        AnalysisRepository(session),
        ScanRepository(session),
        AssessmentRepository(session),
        session,
        clock,
    )


def get_report_service(session: SessionDep, clock: ClockDep) -> ReportService:
    return ReportService(
        ReportRepository(session),
        ScanRepository(session),
        AssessmentRepository(session),
        session,
        session,
        clock,
    )


def get_retest_service(session: SessionDep, clock: ClockDep) -> RetestService:
    return RetestService(
        AssessmentRepository(session),
        TargetRepository(session),
        ScanRepository(session),
        ComparisonRepository(session),
        session,
        clock,
    )


def get_comparison_service(session: SessionDep) -> ComparisonService:
    return ComparisonService(
        ComparisonRepository(session),
        AssessmentRepository(session),
        ScanRepository(session),
        session,
    )


def get_retest_report_service(session: SessionDep, clock: ClockDep) -> RetestReportService:
    return RetestReportService(
        RetestReportRepository(session), AssessmentRepository(session), session, session, clock
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
