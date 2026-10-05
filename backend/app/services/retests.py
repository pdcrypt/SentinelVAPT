"""Retests (ADR 0011).

A retest is an ordinary assessment of the same target with two immutable
links: the completed assessment it retests (its parent) and the parent's
analysed scan it is measured against (its baseline). It is planned under the
target's current authorization, whose scope must be contained in the
parent's: a retest can narrow scope, never widen it. Once created it follows
the normal assessment lifecycle (start, scans, complete), with every Phase 1-3
authorization and scope check unchanged.
"""

import uuid
from collections.abc import Sequence
from typing import Any

from app.core.actors import UserActor, require_user_actor
from app.core.clock import Clock
from app.core.errors import NotFoundError, RetestNotAllowedError
from app.models import Assessment, Comparison
from app.models.enums import AssessmentStatus, AuthorizationStatus, ScanStatus, TargetEnvironment
from app.repositories import (
    AssessmentRepository,
    ComparisonRepository,
    ScanRepository,
    TargetRepository,
)
from app.schemas.retest import RetestCreate
from app.services.base import UnitOfWork
from app.services.scope import authorization_status, scope_expansion

MAX_LINEAGE = 1000


class RetestService:
    def __init__(
        self,
        assessments: AssessmentRepository,
        targets: TargetRepository,
        scans: ScanRepository,
        comparisons: ComparisonRepository,
        uow: UnitOfWork,
        clock: Clock,
    ) -> None:
        self.assessments = assessments
        self.targets = targets
        self.scans = scans
        self.comparisons = comparisons
        self.uow = uow
        self.clock = clock

    def create(self, parent_id: uuid.UUID, data: RetestCreate, *, actor: UserActor) -> Assessment:
        actor = require_user_actor(actor)
        # Lock order: assessment -> target. Holding the parent's lock serializes
        # concurrent retest requests for it (the partial unique index is the
        # database backstop).
        parent = self.assessments.get_for_update(parent_id)
        if parent is None:
            raise NotFoundError("assessment not found")
        target = self.targets.get_for_update(parent.target_id)
        if target is None:  # pragma: no cover  # prevented by foreign keys
            raise NotFoundError("target not found")
        if parent.status is not AssessmentStatus.COMPLETED:
            raise RetestNotAllowedError(
                "parent_not_completed", "only a completed assessment can be retested"
            )

        if data.baseline_scan_id is not None:
            baseline = self.scans.get(data.baseline_scan_id)
            if baseline is None or baseline.assessment_id != parent.id:
                raise NotFoundError("scan not found in this assessment", field="baseline_scan_id")
            if baseline.status is not ScanStatus.COMPLETED:
                raise RetestNotAllowedError(
                    "baseline_not_completed", "the baseline scan did not complete"
                )
            if self.comparisons.completed_run(baseline.id) is None:
                raise RetestNotAllowedError(
                    "baseline_not_analysed", "the baseline scan has no completed analysis"
                )
        else:
            latest = self.comparisons.latest_analysed_scan(parent.id)
            if latest is None:
                raise RetestNotAllowedError(
                    "baseline_not_analysed",
                    "the assessment has no completed scan with a completed analysis",
                )
            baseline = latest

        if self.comparisons.live_retest(parent.id) is not None:
            raise RetestNotAllowedError(
                "retest_exists", "this assessment already has a retest that is not cancelled"
            )

        authorization = target.current_authorization
        status = authorization_status(
            authorization.valid_from, authorization.valid_until, self.clock()
        )
        if status is AuthorizationStatus.EXPIRED:
            raise RetestNotAllowedError(
                "authorization_expired",
                "the target's authorization has expired; renew it before planning a retest",
            )
        if authorization.environment is not TargetEnvironment.LOCAL_LAB:
            raise RetestNotAllowedError(
                "authorization_not_local_lab", "retests are limited to local_lab targets"
            )
        expansion = scope_expansion(authorization, parent.authorization)
        if expansion is not None:
            raise RetestNotAllowedError(
                "scope_expanded",
                f"the target's current scope is wider than the parent assessment's: {expansion}",
            )

        retest = self.assessments.add(
            Assessment(
                target_id=target.id,
                authorization_id=authorization.id,
                name=data.name,
                description=data.description,
                retest_of_assessment_id=parent.id,
                baseline_scan_id=baseline.id,
                created_by_user_id=actor.user_id,
            )
        )
        self.uow.commit()
        return retest

    def list_retests(self, assessment_id: uuid.UUID) -> Sequence[Assessment]:
        if self.assessments.get(assessment_id) is None:
            raise NotFoundError("assessment not found")
        return self.comparisons.retests_of(assessment_id)

    def lineage(self, assessment_id: uuid.UUID) -> list[dict[str, Any]]:
        """The chain from the original assessment to this one."""
        assessment = self.assessments.get(assessment_id)
        if assessment is None:
            raise NotFoundError("assessment not found")
        chain: list[Assessment] = [assessment]
        while chain[-1].retest_of_assessment_id is not None and len(chain) < MAX_LINEAGE:
            parent = self.assessments.get(chain[-1].retest_of_assessment_id)
            assert parent is not None  # noqa: S101  # foreign key
            chain.append(parent)
        chain.reverse()
        entries = []
        for position, item in enumerate(chain):
            comparisons: Sequence[Comparison] = self.comparisons.list_for_assessment(item.id)
            entries.append(
                {
                    "position": position,
                    "assessment_id": item.id,
                    "name": item.name,
                    "status": item.status,
                    "authorization_id": item.authorization_id,
                    "retest_of_assessment_id": item.retest_of_assessment_id,
                    "baseline_scan_id": item.baseline_scan_id,
                    "comparisons": [
                        {
                            "id": c.id,
                            "current_scan_id": c.current_scan_id,
                            "status": c.status,
                            "policy_version": c.policy_version,
                        }
                        for c in comparisons
                    ],
                }
            )
        return entries
