import uuid
from collections.abc import Sequence

from fastapi import APIRouter, Depends, status

from app.api.authz import authorize
from app.api.deps import AssessmentServiceDep, Limit, Offset
from app.core.authz import Permission as P
from app.core.authz import ResourceType as R
from app.models import Assessment
from app.schemas.assessment import AssessmentCreate, AssessmentRead, AssessmentUpdate

router = APIRouter(tags=["assessments"])


@router.post(
    "/targets/{target_id}/assessments",
    dependencies=[Depends(authorize(P.ASSESSMENT_WRITE, R.TARGET, "target_id"))],
    response_model=AssessmentRead,
    status_code=status.HTTP_201_CREATED,
)
def create_assessment(
    target_id: uuid.UUID, data: AssessmentCreate, service: AssessmentServiceDep
) -> Assessment:
    return service.create(target_id, data)


@router.get(
    "/targets/{target_id}/assessments",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.TARGET, "target_id"))],
    response_model=list[AssessmentRead],
)
def list_target_assessments(
    target_id: uuid.UUID, service: AssessmentServiceDep, limit: Limit = 50, offset: Offset = 0
) -> Sequence[Assessment]:
    return service.list_for_target(target_id, limit=limit, offset=offset)


@router.get(
    "/projects/{project_id}/assessments",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.PROJECT, "project_id"))],
    response_model=list[AssessmentRead],
)
def list_project_assessments(
    project_id: uuid.UUID, service: AssessmentServiceDep, limit: Limit = 50, offset: Offset = 0
) -> Sequence[Assessment]:
    return service.list_for_project(project_id, limit=limit, offset=offset)


@router.get(
    "/assessments/{assessment_id}",
    dependencies=[Depends(authorize(P.PROJECT_READ, R.ASSESSMENT, "assessment_id"))],
    response_model=AssessmentRead,
)
def get_assessment(assessment_id: uuid.UUID, service: AssessmentServiceDep) -> Assessment:
    return service.get(assessment_id)


@router.patch(
    "/assessments/{assessment_id}",
    dependencies=[Depends(authorize(P.ASSESSMENT_WRITE, R.ASSESSMENT, "assessment_id"))],
    response_model=AssessmentRead,
)
def update_assessment(
    assessment_id: uuid.UUID, data: AssessmentUpdate, service: AssessmentServiceDep
) -> Assessment:
    return service.update(assessment_id, data)


@router.delete(
    "/assessments/{assessment_id}",
    dependencies=[Depends(authorize(P.ASSESSMENT_DELETE, R.ASSESSMENT, "assessment_id"))],
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_assessment(assessment_id: uuid.UUID, service: AssessmentServiceDep) -> None:
    service.delete(assessment_id)


# Status changes are explicit actions rather than a writable `status` field, so
# each transition goes through its own rules (e.g. start requires active authorization).


@router.post(
    "/assessments/{assessment_id}/start",
    dependencies=[Depends(authorize(P.ASSESSMENT_WRITE, R.ASSESSMENT, "assessment_id"))],
    response_model=AssessmentRead,
)
def start_assessment(assessment_id: uuid.UUID, service: AssessmentServiceDep) -> Assessment:
    return service.start(assessment_id)


@router.post(
    "/assessments/{assessment_id}/complete",
    dependencies=[Depends(authorize(P.ASSESSMENT_WRITE, R.ASSESSMENT, "assessment_id"))],
    response_model=AssessmentRead,
)
def complete_assessment(assessment_id: uuid.UUID, service: AssessmentServiceDep) -> Assessment:
    return service.complete(assessment_id)


@router.post(
    "/assessments/{assessment_id}/cancel",
    dependencies=[Depends(authorize(P.ASSESSMENT_WRITE, R.ASSESSMENT, "assessment_id"))],
    response_model=AssessmentRead,
)
def cancel_assessment(assessment_id: uuid.UUID, service: AssessmentServiceDep) -> Assessment:
    return service.cancel(assessment_id)
