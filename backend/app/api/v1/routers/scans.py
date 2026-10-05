import uuid
from collections.abc import Sequence
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.authz import authorize
from app.api.deps import Limit, Offset, ScanServiceDep
from app.core.actors import UserActor
from app.core.authz import AccessDecision
from app.core.authz import Permission as P
from app.core.authz import ResourceType as R
from app.models import Asset, Evidence, Scan, ScanLog
from app.schemas.common import TextQuery
from app.schemas.scan import (
    AssetRead,
    CookieRead,
    EndpointRead,
    EvidenceRead,
    ScanCreate,
    ScanLogRead,
    ScanRead,
)

router = APIRouter(tags=["scans"])


@router.post(
    "/assessments/{assessment_id}/scans",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
)
def create_scan(
    assessment_id: uuid.UUID,
    service: ScanServiceDep,
    access: Annotated[
        AccessDecision, Depends(authorize(P.SCAN_RUN, R.ASSESSMENT, "assessment_id"))
    ],
    data: ScanCreate | None = None,
) -> Scan:
    """Queue a discovery scan. It is executed by the worker, not in this request;
    the requester is the authenticated user."""
    return service.create(assessment_id, data or ScanCreate(), actor=UserActor.of(access.principal))


@router.get(
    "/assessments/{assessment_id}/scans",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.ASSESSMENT, "assessment_id"))],
    response_model=list[ScanRead],
)
def list_scans(
    assessment_id: uuid.UUID, service: ScanServiceDep, limit: Limit = 50, offset: Offset = 0
) -> Sequence[Scan]:
    return service.list_for_assessment(assessment_id, limit=limit, offset=offset)


@router.get(
    "/scans/{scan_id}",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.SCAN, "scan_id"))],
    response_model=ScanRead,
)
def get_scan(scan_id: uuid.UUID, service: ScanServiceDep) -> Scan:
    return service.get(scan_id)


@router.post(
    "/scans/{scan_id}/cancel",
    dependencies=[Depends(authorize(P.SCAN_RUN, R.SCAN, "scan_id"))],
    response_model=ScanRead,
)
def cancel_scan(scan_id: uuid.UUID, service: ScanServiceDep) -> Scan:
    return service.cancel(scan_id)


@router.get(
    "/scans/{scan_id}/logs",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.SCAN, "scan_id"))],
    response_model=list[ScanLogRead],
)
def list_scan_logs(
    scan_id: uuid.UUID, service: ScanServiceDep, limit: Limit = 50, offset: Offset = 0
) -> Sequence[ScanLog]:
    return service.logs(scan_id, limit=limit, offset=offset)


@router.get(
    "/scans/{scan_id}/assets",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.SCAN, "scan_id"))],
    response_model=list[AssetRead],
)
def list_scan_assets(
    scan_id: uuid.UUID, service: ScanServiceDep, limit: Limit = 50, offset: Offset = 0
) -> Sequence[Asset]:
    return service.assets(scan_id, limit=limit, offset=offset)


@router.get(
    "/scans/{scan_id}/endpoints",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.SCAN, "scan_id"))],
    response_model=list[EndpointRead],
)
def list_scan_endpoints(
    scan_id: uuid.UUID,
    service: ScanServiceDep,
    limit: Limit = 50,
    offset: Offset = 0,
    fetched: bool | None = None,
    skip_reason: Annotated[TextQuery | None, Query(max_length=32)] = None,
    source: Annotated[TextQuery | None, Query(max_length=32)] = None,
    method: Annotated[TextQuery | None, Query(max_length=16)] = None,
) -> list[EndpointRead]:
    rows = service.endpoints(
        scan_id,
        limit=limit,
        offset=offset,
        fetched=fetched,
        skip_reason=skip_reason,
        source=source,
        method=method,
    )
    return [
        EndpointRead.model_validate(endpoint).model_copy(
            update={"cookies": [CookieRead.model_validate(c) for c in cookies]}
        )
        for endpoint, cookies in rows
    ]


@router.get(
    "/scans/{scan_id}/evidence",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.SCAN, "scan_id"))],
    response_model=list[EvidenceRead],
)
def list_scan_evidence(
    scan_id: uuid.UUID, service: ScanServiceDep, limit: Limit = 50, offset: Offset = 0
) -> Sequence[Evidence]:
    return service.evidence(scan_id, limit=limit, offset=offset)


@router.get(
    "/evidence/{evidence_id}",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.EVIDENCE, "evidence_id"))],
    response_model=EvidenceRead,
)
def get_evidence(evidence_id: uuid.UUID, service: ScanServiceDep) -> Evidence:
    return service.get_evidence(evidence_id)
