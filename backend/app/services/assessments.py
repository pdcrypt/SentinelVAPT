import uuid
from collections.abc import Sequence

from app.core.clock import Clock
from app.core.errors import (
    ConflictError,
    InvalidStateTransitionError,
    NotFoundError,
    TargetAuthorizationError,
)
from app.models import Assessment, TargetAuthorization
from app.models.enums import AssessmentStatus, AuthorizationStatus
from app.repositories import AssessmentRepository, ProjectRepository, TargetRepository
from app.schemas.assessment import AssessmentCreate, AssessmentUpdate
from app.services.base import UnitOfWork
from app.services.scope import authorization_status

ALLOWED_TRANSITIONS: dict[AssessmentStatus, frozenset[AssessmentStatus]] = {
    AssessmentStatus.PLANNED: frozenset({AssessmentStatus.IN_PROGRESS, AssessmentStatus.CANCELLED}),
    AssessmentStatus.IN_PROGRESS: frozenset(
        {AssessmentStatus.COMPLETED, AssessmentStatus.CANCELLED}
    ),
    AssessmentStatus.COMPLETED: frozenset(),
    AssessmentStatus.CANCELLED: frozenset(),
}

DELETABLE_STATUSES = frozenset({AssessmentStatus.PLANNED, AssessmentStatus.CANCELLED})


def ensure_transition(current: AssessmentStatus, new: AssessmentStatus) -> None:
    if new not in ALLOWED_TRANSITIONS[current]:
        raise InvalidStateTransitionError(
            f"cannot move an assessment from '{current}' to '{new}'", field="status"
        )


class AssessmentService:
    def __init__(
        self,
        assessments: AssessmentRepository,
        targets: TargetRepository,
        projects: ProjectRepository,
        uow: UnitOfWork,
        clock: Clock,
    ) -> None:
        self.assessments = assessments
        self.targets = targets
        self.projects = projects
        self.uow = uow
        self.clock = clock

    def create(self, target_id: uuid.UUID, data: AssessmentCreate) -> Assessment:
        # Locked so the authorization recorded below cannot be superseded mid-request.
        target = self.targets.get_for_update(target_id)
        if target is None:
            raise NotFoundError("target not found")
        authorization = target.current_authorization
        # Planning ahead of a future window is fine; planning against an ended one is not.
        if self._authorization_status(authorization) is AuthorizationStatus.EXPIRED:
            raise TargetAuthorizationError(
                "the target's authorization has expired; renew it before planning an assessment"
            )
        assessment = self.assessments.add(
            Assessment(
                target_id=target.id,
                authorization_id=authorization.id,
                name=data.name,
                description=data.description,
            )
        )
        self.uow.commit()
        return assessment

    def get(self, assessment_id: uuid.UUID) -> Assessment:
        assessment = self.assessments.get(assessment_id)
        if assessment is None:
            raise NotFoundError("assessment not found")
        return assessment

    def list_for_target(
        self, target_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[Assessment]:
        if self.targets.get(target_id) is None:
            raise NotFoundError("target not found")
        return self.assessments.list_for_target(target_id, limit=limit, offset=offset)

    def list_for_project(
        self, project_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[Assessment]:
        if self.projects.get(project_id) is None:
            raise NotFoundError("project not found")
        return self.assessments.list_for_project(project_id, limit=limit, offset=offset)

    def update(self, assessment_id: uuid.UUID, data: AssessmentUpdate) -> Assessment:
        assessment = self._get_for_update(assessment_id)
        for field, value in data.model_dump(exclude_unset=True).items():
            setattr(assessment, field, value)
        self.assessments.flush()
        self.uow.commit()
        return assessment

    def start(self, assessment_id: uuid.UUID) -> Assessment:
        # Lock order: assessment, then target. No code path locks a target and
        # then an existing assessment, so this order cannot deadlock.
        assessment = self._get_for_update(assessment_id)
        ensure_transition(assessment.status, AssessmentStatus.IN_PROGRESS)
        target = self.targets.get_for_update(assessment.target_id)
        if target is None:  # pragma: no cover  # prevented by the foreign key
            raise NotFoundError("target not found")
        if target.current_authorization_id != assessment.authorization_id:
            raise TargetAuthorizationError(
                "the target was re-authorized after this assessment was planned, so its "
                "scope or authorization may differ; plan a new assessment under the "
                "current authorization"
            )
        status = self._authorization_status(assessment.authorization)
        if status is not AuthorizationStatus.ACTIVE:
            raise TargetAuthorizationError(
                f"the target's authorization is {status}; an assessment can only start "
                "while it is active"
            )
        assessment.status = AssessmentStatus.IN_PROGRESS
        assessment.started_at = self.clock()
        return self._save(assessment)

    def complete(self, assessment_id: uuid.UUID) -> Assessment:
        assessment = self._get_for_update(assessment_id)
        ensure_transition(assessment.status, AssessmentStatus.COMPLETED)
        assessment.status = AssessmentStatus.COMPLETED
        assessment.completed_at = self.clock()
        return self._save(assessment)

    def cancel(self, assessment_id: uuid.UUID) -> Assessment:
        assessment = self._get_for_update(assessment_id)
        ensure_transition(assessment.status, AssessmentStatus.CANCELLED)
        assessment.status = AssessmentStatus.CANCELLED
        return self._save(assessment)

    def delete(self, assessment_id: uuid.UUID) -> None:
        assessment = self._get_for_update(assessment_id)
        if assessment.status not in DELETABLE_STATUSES:
            raise ConflictError(
                f"a {assessment.status} assessment cannot be deleted; only planned or "
                "cancelled assessments can"
            )
        self.assessments.delete(assessment)
        self.uow.commit()

    def _get_for_update(self, assessment_id: uuid.UUID) -> Assessment:
        """Every state-changing operation reads the assessment under a row lock,
        so a stale read can never overwrite a concurrently committed transition
        (e.g. a cancel undone by a start that had read 'planned')."""
        assessment = self.assessments.get_for_update(assessment_id)
        if assessment is None:
            raise NotFoundError("assessment not found")
        return assessment

    def _save(self, assessment: Assessment) -> Assessment:
        self.assessments.flush()
        self.uow.commit()
        return assessment

    def _authorization_status(self, authorization: TargetAuthorization) -> AuthorizationStatus:
        return authorization_status(
            authorization.valid_from, authorization.valid_until, self.clock()
        )
