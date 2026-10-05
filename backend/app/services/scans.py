import uuid
from collections.abc import Sequence

from app.core.actors import UserActor, require_user_actor
from app.core.clock import Clock
from app.core.errors import InvalidStateTransitionError, NotFoundError, ScanNotAllowedError
from app.models import Asset, Endpoint, EndpointCookie, Evidence, Scan, ScanLog
from app.models.enums import ScanStatus
from app.repositories import (
    AssessmentRepository,
    ScanRepository,
    ScanResultRepository,
    TargetRepository,
)
from app.schemas.scan import ScanCreate
from app.services.base import UnitOfWork
from app.services.scan_grants import build_scan_grant, scan_config_record

USER_CANCEL_REASON = "user_request"


class ScanService:
    """Scan requests and reads. Scans are executed by the worker (app.worker),
    never inside an API request."""

    def __init__(
        self,
        scans: ScanRepository,
        results: ScanResultRepository,
        assessments: AssessmentRepository,
        targets: TargetRepository,
        uow: UnitOfWork,
        clock: Clock,
    ) -> None:
        self.scans = scans
        self.results = results
        self.assessments = assessments
        self.targets = targets
        self.uow = uow
        self.clock = clock

    def create(self, assessment_id: uuid.UUID, data: ScanCreate, *, actor: UserActor) -> Scan:
        actor = require_user_actor(actor)
        # Lock order: assessment -> target (-> scan). Holding the assessment lock
        # also serializes concurrent requests for the same assessment.
        assessment = self.assessments.get_for_update(assessment_id)
        if assessment is None:
            raise NotFoundError("assessment not found")
        target = self.targets.get_for_update(assessment.target_id)
        if target is None:  # pragma: no cover  # prevented by foreign keys
            raise NotFoundError("target not found")

        # Same rules the worker applies at claim time; refusing here gives the
        # caller an immediate answer. The grant itself is built again at claim.
        build_scan_grant(assessment, target, target.current_authorization, self.clock())
        if self.scans.has_active(assessment.id):
            raise ScanNotAllowedError(
                "active_scan_exists", "this assessment already has a queued or running scan"
            )

        scan = Scan(
            assessment_id=assessment.id,
            target_id=target.id,
            authorization_id=assessment.authorization_id,
            status=ScanStatus.QUEUED,
            config=scan_config_record(allow_untrusted_tls=data.allow_untrusted_tls),
            # Who requested the scan; the worker that runs it is recorded
            # separately (claimed_by) and never changes this.
            requested_by_user_id=actor.user_id,
        )
        self.scans.add(scan)
        self.uow.commit()
        return scan

    def get(self, scan_id: uuid.UUID) -> Scan:
        scan = self.scans.get(scan_id)
        if scan is None:
            raise NotFoundError("scan not found")
        return scan

    def list_for_assessment(
        self, assessment_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[Scan]:
        if self.assessments.get(assessment_id) is None:
            raise NotFoundError("assessment not found")
        return self.scans.list_for_assessment(assessment_id, limit=limit, offset=offset)

    def cancel(self, scan_id: uuid.UUID) -> Scan:
        """Queued: cancelled at once. Running: cancellation is requested and the
        worker stops the scanner at its next check. Terminal: refused."""
        scan = self.scans.get_for_update(scan_id)  # scan lock only
        if scan is None:
            raise NotFoundError("scan not found")
        now = self.clock()
        if scan.status is ScanStatus.QUEUED:
            scan.status = ScanStatus.CANCELLED
            scan.cancel_requested_at = now
            scan.cancel_reason = USER_CANCEL_REASON
            scan.finished_at = now
        elif scan.status is ScanStatus.RUNNING:
            if scan.cancel_requested_at is None:
                scan.cancel_requested_at = now
                scan.cancel_reason = USER_CANCEL_REASON
        else:
            raise InvalidStateTransitionError(
                f"a {scan.status} scan cannot be cancelled", field="status"
            )
        self.scans.flush()
        self.uow.commit()
        return scan

    # --- results (read-only) ------------------------------------------------------

    def logs(self, scan_id: uuid.UUID, *, limit: int, offset: int) -> Sequence[ScanLog]:
        self.get(scan_id)
        return self.results.list_logs(scan_id, limit=limit, offset=offset)

    def assets(self, scan_id: uuid.UUID, *, limit: int, offset: int) -> Sequence[Asset]:
        self.get(scan_id)
        return self.results.list_assets(scan_id, limit=limit, offset=offset)

    def endpoints(
        self,
        scan_id: uuid.UUID,
        *,
        limit: int,
        offset: int,
        fetched: bool | None = None,
        skip_reason: str | None = None,
        source: str | None = None,
        method: str | None = None,
    ) -> list[tuple[Endpoint, list[EndpointCookie]]]:
        self.get(scan_id)
        endpoints = self.results.list_endpoints(
            scan_id,
            limit=limit,
            offset=offset,
            fetched=fetched,
            skip_reason=skip_reason,
            source=source,
            method=method,
        )
        cookies: dict[uuid.UUID, list[EndpointCookie]] = {}
        for cookie in self.results.cookies_for([e.id for e in endpoints]):
            cookies.setdefault(cookie.endpoint_id, []).append(cookie)
        return [(e, cookies.get(e.id, [])) for e in endpoints]

    def evidence(self, scan_id: uuid.UUID, *, limit: int, offset: int) -> Sequence[Evidence]:
        self.get(scan_id)
        return self.results.list_evidence(scan_id, limit=limit, offset=offset)

    def get_evidence(self, evidence_id: uuid.UUID) -> Evidence:
        evidence = self.results.get_evidence(evidence_id)
        if evidence is None:
            raise NotFoundError("evidence not found")
        return evidence
