import uuid
from typing import Any

from fastapi import APIRouter, Depends, Response, status

from app.api.authz import authorize, require_global
from app.api.deps import Limit, Offset, RetestReportServiceDep
from app.api.v1.routers.reports import DOWNLOAD_CSP, EXTENSIONS, PREVIEW_CSP
from app.core.authz import Permission as P
from app.core.authz import ResourceType as R
from app.models import RetestReport
from app.models.enums import ReportFormat
from app.schemas.report import ArtifactRead, ReportTemplateRead
from app.schemas.retest_report import RetestReportCreate, RetestReportRead
from app.services.retest_reports import RetestReportService, display_retest_number

router = APIRouter(tags=["retest-reports"])


def _read(report: RetestReport, artifacts: list[dict[str, Any]]) -> RetestReportRead:
    values = {c.key: getattr(report, c.key) for c in RetestReport.__table__.columns}
    values.pop("snapshot")
    return RetestReportRead.model_validate(
        {**values, "number": display_retest_number(report.number), "artifacts": artifacts}
    )


def _headers(sha256: str) -> dict[str, str]:
    return {
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "ETag": f'"{sha256}"',
    }


@router.post(
    "/assessments/{assessment_id}/comparisons/{comparison_id}/reports",
    dependencies=[
        Depends(
            authorize(
                P.REPORT_REQUEST,
                R.ASSESSMENT_COMPARISON,
                key={"assessment_id": "assessment_id", "comparison_id": "comparison_id"},
            )
        )
    ],
    response_model=RetestReportRead,
    status_code=status.HTTP_202_ACCEPTED,
    responses={200: {"description": "An identical report already exists."}},
)
def create_retest_report(
    assessment_id: uuid.UUID,
    comparison_id: uuid.UUID,
    data: RetestReportCreate,
    service: RetestReportServiceDep,
    response: Response,
) -> RetestReportRead:
    """Freeze a snapshot of a completed comparison and queue its report. An
    identical request returns the existing report (200)."""
    report, created = service.create(assessment_id, comparison_id, data)
    if not created:
        response.status_code = status.HTTP_200_OK
    return _read(report, service.artifacts([report.id])[report.id])


@router.get(
    "/assessments/{assessment_id}/retest-reports",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.ASSESSMENT, "assessment_id"))],
    response_model=list[RetestReportRead],
)
def list_retest_reports(
    assessment_id: uuid.UUID,
    service: RetestReportServiceDep,
    limit: Limit = 50,
    offset: Offset = 0,
) -> list[RetestReportRead]:
    reports = service.list_for_assessment(assessment_id, limit=limit, offset=offset)
    artifacts = service.artifacts([r.id for r in reports])
    return [_read(r, artifacts[r.id]) for r in reports]


@router.get(
    "/retest-reports/{report_id}",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.RETEST_REPORT, "report_id"))],
    response_model=RetestReportRead,
)
def get_retest_report(report_id: uuid.UUID, service: RetestReportServiceDep) -> RetestReportRead:
    report = service.get(report_id)
    return _read(report, service.artifacts([report.id])[report.id])


@router.get(
    "/retest-reports/{report_id}/artifacts",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.RETEST_REPORT, "report_id"))],
    response_model=list[ArtifactRead],
)
def list_retest_artifacts(
    report_id: uuid.UUID, service: RetestReportServiceDep
) -> list[dict[str, Any]]:
    report = service.get(report_id)
    return service.artifacts([report.id])[report.id]


@router.get(
    "/retest-reports/{report_id}/artifacts/{fmt}",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.RETEST_REPORT, "report_id"))],
)
def download_retest_artifact(
    report_id: uuid.UUID, fmt: ReportFormat, service: RetestReportServiceDep
) -> Response:
    report, artifact = service.artifact(report_id, fmt.value)
    filename = f"{display_retest_number(report.number)}.{EXTENSIONS[artifact.format]}"
    return Response(
        content=artifact.content,
        media_type=artifact.media_type,
        headers={
            **_headers(artifact.sha256),
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Security-Policy": DOWNLOAD_CSP,
        },
    )


@router.get(
    "/retest-reports/{report_id}/preview",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.RETEST_REPORT, "report_id"))],
)
def preview_retest_report(report_id: uuid.UUID, service: RetestReportServiceDep) -> Response:
    _, artifact = service.artifact(report_id, ReportFormat.HTML.value)
    return Response(
        content=artifact.content,
        media_type="text/html; charset=utf-8",
        headers={
            **_headers(artifact.sha256),
            "Content-Disposition": "inline",
            "Content-Security-Policy": PREVIEW_CSP,
        },
    )


@router.get(
    "/retest-report-templates",
    dependencies=[Depends(require_global(P.CATALOG_READ))],
    response_model=list[ReportTemplateRead],
)
def list_retest_report_templates() -> list[dict[str, Any]]:
    return RetestReportService.templates()
