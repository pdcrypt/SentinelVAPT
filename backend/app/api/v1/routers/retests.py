import uuid
from collections.abc import Sequence
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response, status

from app.api.authz import authorize
from app.api.deps import ComparisonServiceDep, Limit, Offset, RetestServiceDep
from app.core.actors import UserActor
from app.core.authz import AccessDecision
from app.core.authz import Permission as P
from app.core.authz import ResourceType as R
from app.models import Assessment, Comparison
from app.models.enums import ComparisonState
from app.schemas.assessment import AssessmentRead
from app.schemas.finding import RuleIdStr
from app.schemas.retest import (
    ComparisonCreate,
    ComparisonRead,
    ComparisonRecordRead,
    FingerprintStr,
    LineageEntry,
    RetestCreate,
)

router = APIRouter(tags=["retests"])


@router.post(
    "/assessments/{assessment_id}/retests",
    response_model=AssessmentRead,
    status_code=status.HTTP_201_CREATED,
)
def create_retest(
    assessment_id: uuid.UUID,
    data: RetestCreate,
    service: RetestServiceDep,
    access: Annotated[
        AccessDecision, Depends(authorize(P.RETEST_WRITE, R.ASSESSMENT, "assessment_id"))
    ],
) -> Assessment:
    """Plan a retest of a completed assessment, measured against one of its
    analysed scans. It then follows the normal assessment lifecycle."""
    return service.create(assessment_id, data, actor=UserActor.of(access.principal))


@router.get(
    "/assessments/{assessment_id}/retests",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.ASSESSMENT, "assessment_id"))],
    response_model=list[AssessmentRead],
)
def list_retests(assessment_id: uuid.UUID, service: RetestServiceDep) -> Sequence[Assessment]:
    return service.list_retests(assessment_id)


@router.get(
    "/assessments/{assessment_id}/lineage",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.ASSESSMENT, "assessment_id"))],
    response_model=list[LineageEntry],
)
def get_lineage(assessment_id: uuid.UUID, service: RetestServiceDep) -> list[dict[str, Any]]:
    return service.lineage(assessment_id)


@router.post(
    "/assessments/{assessment_id}/comparisons",
    response_model=ComparisonRead,
    status_code=status.HTTP_202_ACCEPTED,
    responses={200: {"description": "The comparison already exists for this scan and policy."}},
)
def request_comparison(
    assessment_id: uuid.UUID,
    data: ComparisonCreate,
    service: ComparisonServiceDep,
    response: Response,
    access: Annotated[
        AccessDecision, Depends(authorize(P.RETEST_WRITE, R.ASSESSMENT, "assessment_id"))
    ],
) -> Comparison:
    """Queue the comparison of a retest scan with its baseline (computed by the
    worker, offline, from persisted data). Idempotent per scan and policy."""
    comparison, created = service.request(
        assessment_id, data.scan_id, actor=UserActor.of(access.principal)
    )
    if not created:
        response.status_code = status.HTTP_200_OK
    return comparison


@router.get(
    "/assessments/{assessment_id}/comparisons",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.ASSESSMENT, "assessment_id"))],
    response_model=list[ComparisonRead],
)
def list_comparisons(
    assessment_id: uuid.UUID, service: ComparisonServiceDep
) -> Sequence[Comparison]:
    return service.list_for_assessment(assessment_id)


@router.get(
    "/comparisons/{comparison_id}",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.COMPARISON, "comparison_id"))],
    response_model=ComparisonRead,
)
def get_comparison(comparison_id: uuid.UUID, service: ComparisonServiceDep) -> Comparison:
    return service.get(comparison_id)


@router.get(
    "/comparisons/{comparison_id}/records",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.COMPARISON, "comparison_id"))],
    response_model=list[ComparisonRecordRead],
)
def list_comparison_records(
    comparison_id: uuid.UUID,
    service: ComparisonServiceDep,
    limit: Limit = 50,
    offset: Offset = 0,
    state: ComparisonState | None = None,
    rule_id: RuleIdStr | None = None,
) -> list[dict[str, Any]]:
    return service.records(
        comparison_id,
        state=state.value if state else None,
        rule_id=rule_id,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/comparisons/{comparison_id}/records/{fingerprint}",
    dependencies=[
        Depends(
            authorize(
                P.PROJECT_READ,
                R.COMPARISON_RECORD,
                key={"comparison_id": "comparison_id", "fingerprint": "fingerprint"},
            )
        )
    ],
    response_model=ComparisonRecordRead,
)
def get_comparison_record(
    comparison_id: uuid.UUID, fingerprint: FingerprintStr, service: ComparisonServiceDep
) -> dict[str, Any]:
    return service.record(comparison_id, fingerprint)
