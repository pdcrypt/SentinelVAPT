import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response, status

from app.api.authz import authorize, require_global
from app.api.deps import Limit, Offset, ReportServiceDep
from app.core.actors import UserActor
from app.core.authz import AccessDecision
from app.core.authz import Permission as P
from app.core.authz import ResourceType as R
from app.models import Report
from app.models.enums import ReportFormat
from app.schemas.report import ArtifactRead, ReportCreate, ReportRead, ReportTemplateRead
from app.services.reports import ReportService, display_number

router = APIRouter(tags=["reports"])

# The HTML preview runs in a sandbox with no scripts, no network and no
# framing by other origins, even though report HTML contains none of these.
PREVIEW_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'self'; sandbox"
)
DOWNLOAD_CSP = "default-src 'none'; sandbox"
EXTENSIONS = {"json": "json", "html": "html", "pdf": "pdf"}


def _read(report: Report, artifacts: list[dict[str, Any]]) -> ReportRead:
    values = {c.key: getattr(report, c.key) for c in Report.__table__.columns}
    values.pop("snapshot")
    return ReportRead.model_validate(
        {**values, "number": display_number(report.number), "artifacts": artifacts}
    )


def _security_headers(sha256: str) -> dict[str, str]:
    return {
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "ETag": f'"{sha256}"',
    }


@router.post(
    "/assessments/{assessment_id}/reports",
    response_model=ReportRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_report(
    assessment_id: uuid.UUID,
    data: ReportCreate,
    service: ReportServiceDep,
    access: Annotated[
        AccessDecision, Depends(authorize(P.REPORT_REQUEST, R.ASSESSMENT, "assessment_id"))
    ],
) -> ReportRead:
    """Freeze a snapshot of the scan's findings and evidence and queue the
    report. It is rendered by the report worker, not in this request; it is
    prepared by the authenticated user."""
    report = service.create(assessment_id, data, actor=UserActor.of(access.principal))
    return _read(report, [])


@router.get(
    "/assessments/{assessment_id}/reports",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.ASSESSMENT, "assessment_id"))],
    response_model=list[ReportRead],
)
def list_reports(
    assessment_id: uuid.UUID, service: ReportServiceDep, limit: Limit = 50, offset: Offset = 0
) -> list[ReportRead]:
    reports = service.list_for_assessment(assessment_id, limit=limit, offset=offset)
    artifacts = service.artifacts([r.id for r in reports])
    return [_read(r, artifacts[r.id]) for r in reports]


@router.get(
    "/reports/{report_id}",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.REPORT, "report_id"))],
    response_model=ReportRead,
)
def get_report(report_id: uuid.UUID, service: ReportServiceDep) -> ReportRead:
    report = service.get(report_id)
    return _read(report, service.artifacts([report.id])[report.id])


@router.get(
    "/reports/{report_id}/artifacts",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.REPORT, "report_id"))],
    response_model=list[ArtifactRead],
)
def list_artifacts(report_id: uuid.UUID, service: ReportServiceDep) -> list[dict[str, Any]]:
    report = service.get(report_id)
    return service.artifacts([report.id])[report.id]


@router.get(
    "/reports/{report_id}/artifacts/{fmt}",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.REPORT, "report_id"))],
)
def download_artifact(
    report_id: uuid.UUID, fmt: ReportFormat, service: ReportServiceDep
) -> Response:
    report, artifact = service.artifact(report_id, fmt.value)
    filename = f"{display_number(report.number)}.{EXTENSIONS[artifact.format]}"
    return Response(
        content=artifact.content,
        media_type=artifact.media_type,
        headers={
            **_security_headers(artifact.sha256),
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Security-Policy": DOWNLOAD_CSP,
        },
    )


@router.get(
    "/reports/{report_id}/preview",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.REPORT, "report_id"))],
)
def preview_report(report_id: uuid.UUID, service: ReportServiceDep) -> Response:
    """The HTML artifact, inline, under a sandboxing Content-Security-Policy."""
    _, artifact = service.artifact(report_id, ReportFormat.HTML.value)
    return Response(
        content=artifact.content,
        media_type="text/html; charset=utf-8",
        headers={
            **_security_headers(artifact.sha256),
            "Content-Disposition": "inline",
            "Content-Security-Policy": PREVIEW_CSP,
        },
    )


@router.get(
    "/report-templates",
    dependencies=[Depends(require_global(P.CATALOG_READ))],
    response_model=list[ReportTemplateRead],
)
def list_report_templates() -> list[dict[str, Any]]:
    return ReportService.templates()
