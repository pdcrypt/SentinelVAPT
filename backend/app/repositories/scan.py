import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import exists, func, select, text, update

from app.models import Scan
from app.models.enums import ACTIVE_SCAN_STATUSES, ScanStatus
from app.repositories.base import SqlRepository


@dataclass(frozen=True)
class QueuedCandidate:
    scan_id: uuid.UUID
    assessment_id: uuid.UUID


class ScanRepository(SqlRepository[Scan]):
    model = Scan

    def get_for_update(self, scan_id: uuid.UUID, *, skip_locked: bool = False) -> Scan | None:
        """Lock the scan row until the transaction ends. With skip_locked, a row
        another transaction holds is treated as absent (used to claim work)."""
        stmt = (
            select(Scan)
            .where(Scan.id == scan_id)
            .with_for_update(skip_locked=skip_locked)
            .execution_options(populate_existing=True)
        )
        return self.session.scalars(stmt).one_or_none()

    def list_for_assessment(
        self, assessment_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[Scan]:
        stmt = (
            select(Scan)
            .where(Scan.assessment_id == assessment_id)
            .order_by(Scan.created_at.desc(), Scan.id)
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()

    def active_for_assessment(self, assessment_id: uuid.UUID) -> Sequence[Scan]:
        """Queued/running scans, locked. Callers already hold the assessment
        lock (global order: assessment -> target -> scan)."""
        stmt = (
            select(Scan)
            .where(Scan.assessment_id == assessment_id, Scan.status.in_(ACTIVE_SCAN_STATUSES))
            .order_by(Scan.created_at, Scan.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return self.session.scalars(stmt).all()

    def has_active(self, assessment_id: uuid.UUID) -> bool:
        stmt = select(
            exists().where(
                Scan.assessment_id == assessment_id, Scan.status.in_(ACTIVE_SCAN_STATUSES)
            )
        )
        return bool(self.session.scalar(stmt))

    def has_any(self, assessment_id: uuid.UUID) -> bool:
        return bool(
            self.session.scalar(select(exists().where(Scan.assessment_id == assessment_id)))
        )

    def queued_candidates(self, limit: int) -> list[QueuedCandidate]:
        """Oldest queued scans, *not* locked. Claiming re-checks under locks."""
        stmt = (
            select(Scan.id, Scan.assessment_id)
            .where(Scan.status == ScanStatus.QUEUED)
            .order_by(Scan.created_at, Scan.id)
            .limit(limit)
        )
        return [QueuedCandidate(row.id, row.assessment_id) for row in self.session.execute(stmt)]

    def heartbeat(self, scan_id: uuid.UUID, worker_id: str) -> Scan | None:
        """Record liveness if this worker still owns the running scan; return
        the fresh row (None if ownership was lost, e.g. reaped)."""
        stmt = (
            update(Scan)
            .where(
                Scan.id == scan_id,
                Scan.status == ScanStatus.RUNNING,
                Scan.claimed_by == worker_id,
            )
            .values(heartbeat_at=func.now())
            .returning(Scan)
            .execution_options(populate_existing=True)
        )
        return self.session.scalars(stmt).one_or_none()

    def reap_stale(self, stale_after_seconds: float, now: datetime) -> list[uuid.UUID]:
        """Fail running scans whose worker stopped sending heartbeats. Staleness
        is judged by the database clock, so worker clock skew cannot reap a
        healthy scan. Rows locked by a live finalize are skipped."""
        stale = (
            select(Scan.id)
            .where(
                Scan.status == ScanStatus.RUNNING,
                Scan.heartbeat_at < func.now() - text("make_interval(secs => :stale)"),
            )
            .with_for_update(skip_locked=True)
            .scalar_subquery()
        )
        stmt = (
            update(Scan)
            .where(Scan.id.in_(stale))
            .values(
                status=ScanStatus.FAILED,
                error_code="worker_lost",
                error_message="the worker stopped sending heartbeats",
                finished_at=now,
            )
            .returning(Scan.id)
        )
        return list(self.session.scalars(stmt, {"stale": stale_after_seconds}).all())
