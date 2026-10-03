"""The scan worker (ADR 0008).

Per scan, three phases with strictly separated database access:

1. claim     one short transaction: lock assessment -> target -> scan (SKIP
             LOCKED), re-check every rule, build the ScanGrant from those rows,
             record the audit snapshot, mark the scan running.
2. run       the scanner runs with NO session and NO open transaction. It gets
             only the grant, a DiscoveryConfig and a cancellation token. A
             watcher thread uses its own short transactions to send heartbeats
             and to cancel the scanner if the scan, assessment or authorization
             changes underneath it.
3. finalize  one transaction: lock the scan; if this worker still owns it,
             write all results and the final status together; otherwise drop
             the results (e.g. the scan was reaped).

No automatic retries: a failed scan stays failed.
"""

import logging
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from sqlalchemy import func
from sqlalchemy.orm import Session, sessionmaker

from app.core.clock import Clock, utc_now
from app.core.errors import ScanNotAllowedError
from app.models import Assessment, Target
from app.models.enums import AssessmentStatus, ScanStatus
from app.repositories import (
    AssessmentRepository,
    QueuedCandidate,
    ScanRepository,
    ScanResultRepository,
    TargetRepository,
)
from app.services.scan_grants import build_scan_grant, discovery_config, grant_snapshot
from app.services.scan_results import (
    LogEntry,
    persist_discovery_result,
    persist_logs,
)
from sentinel_scanner import CancellationToken, DiscoveryConfig, DiscoveryResult, run_discovery
from sentinel_scanner.errors import GrantRejected
from sentinel_scanner.grant import ScanGrant
from sentinel_scanner.models import ScanEvent, StopReason
from sentinel_scanner.version import __version__ as scanner_version

logger = logging.getLogger(__name__)

MAX_ERROR_MESSAGE = 1000


class ScannerRunner(Protocol):
    def __call__(
        self,
        grant: ScanGrant,
        config: DiscoveryConfig,
        *,
        cancel: CancellationToken,
        on_event: Callable[[ScanEvent], None],
    ) -> DiscoveryResult: ...


def default_runner(
    grant: ScanGrant,
    config: DiscoveryConfig,
    *,
    cancel: CancellationToken,
    on_event: Callable[[ScanEvent], None],
) -> DiscoveryResult:
    return run_discovery(grant, config, cancel=cancel, on_event=on_event)


@dataclass(frozen=True)
class ClaimedScan:
    scan_id: uuid.UUID
    grant: ScanGrant
    config: DiscoveryConfig
    claimed_at_log: LogEntry


@dataclass
class _RunState:
    token: CancellationToken = field(default_factory=CancellationToken)
    cancel_reason: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def cancel(self, reason: str) -> None:
        with self.lock:
            if self.cancel_reason is None:
                self.cancel_reason = reason
        self.token.cancel()


@dataclass(frozen=True)
class _Failure:
    code: str
    message: str


class Worker:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        worker_id: str,
        runner: ScannerRunner = default_runner,
        clock: Clock = utc_now,
        heartbeat_interval: float = 5.0,
        stale_after: float = 60.0,
        candidate_batch: int = 10,
    ) -> None:
        self.session_factory = session_factory
        self.worker_id = worker_id
        self.runner = runner
        self.clock = clock
        self.heartbeat_interval = heartbeat_interval
        self.stale_after = stale_after
        self.candidate_batch = candidate_batch
        self._current: _RunState | None = None

    # --- loop ---------------------------------------------------------------------

    def run_forever(self, stop: threading.Event, poll_interval: float = 2.0) -> None:
        logger.info("worker %s started", self.worker_id)
        while not stop.is_set():
            try:
                worked = self.run_once()
            except Exception:
                logger.exception("worker iteration failed")
                worked = False
            if not worked:
                stop.wait(poll_interval)
        logger.info("worker %s stopped", self.worker_id)

    def run_once(self) -> bool:
        """Reap stale scans, then claim and execute at most one scan."""
        self.reap_stale()
        claimed = self.claim()
        if claimed is None:
            return False
        self.execute(claimed)
        return True

    def request_shutdown(self) -> None:
        """Stop the running scan cleanly (it ends as cancelled)."""
        state = self._current
        if state is not None:
            state.cancel("worker_shutdown")

    # --- 1. claim -------------------------------------------------------------------

    def claim(self) -> ClaimedScan | None:
        with self.session_factory() as session:
            candidates = ScanRepository(session).queued_candidates(self.candidate_batch)
        for candidate in candidates:
            claimed = self._try_claim(candidate)
            if claimed is not None:
                return claimed
        return None

    def _try_claim(self, candidate: QueuedCandidate) -> ClaimedScan | None:
        with self.session_factory() as session:
            scans = ScanRepository(session)
            # Global lock order: assessment -> target -> scan.
            assessment = AssessmentRepository(session).get_for_update(candidate.assessment_id)
            if assessment is None:
                return None
            target = TargetRepository(session).get_for_update(assessment.target_id)
            scan = scans.get_for_update(candidate.scan_id, skip_locked=True)
            if target is None or scan is None or scan.status is not ScanStatus.QUEUED:
                return None  # another worker or a cancel got there first

            now = self.clock()
            try:
                if scan.authorization_id != assessment.authorization_id:  # pragma: no cover
                    raise ScanNotAllowedError("inconsistent_state", "scan and assessment disagree")
                # Built from the rows locked above, never from the stored snapshot.
                grant = build_scan_grant(assessment, target, target.current_authorization, now)
            except ScanNotAllowedError as exc:
                scan.status = ScanStatus.FAILED
                scan.error_code = exc.reason
                scan.error_message = exc.message[:MAX_ERROR_MESSAGE]
                scan.finished_at = now
                scan.events_count = persist_logs(
                    ScanResultRepository(session),
                    scan.id,
                    [
                        LogEntry(
                            now,
                            "warning",
                            "claim_refused",
                            exc.message,
                            data={"reason": exc.reason},
                        )
                    ],
                )
                session.commit()
                logger.info("scan %s refused at claim: %s", scan.id, exc.reason)
                return None

            scan.status = ScanStatus.RUNNING
            scan.started_at = now
            scan.claimed_by = self.worker_id
            scan.heartbeat_at = func.now()  # database clock
            scan.scanner_version = scanner_version
            scan.grant_snapshot = grant_snapshot(grant)  # audit record only
            config = discovery_config(scan.config)
            session.commit()
            logger.info("scan %s claimed by %s", scan.id, self.worker_id)
            return ClaimedScan(
                scan_id=scan.id,
                grant=grant,
                config=config,
                claimed_at_log=LogEntry(
                    now,
                    "info",
                    "scan_claimed",
                    f"claimed by worker {self.worker_id}",
                    data={
                        "authorization_id": str(grant.authorization_id),
                        "authorization_version": grant.authorization_version,
                        "verify_tls": config.verify_tls,
                    },
                ),
            )

    # --- 2. run ---------------------------------------------------------------------

    def execute(self, claimed: ClaimedScan) -> None:
        state = _RunState()
        self._current = state
        events: list[ScanEvent] = []
        stop_watching = threading.Event()
        watcher = threading.Thread(
            target=self._watch,
            args=(claimed.scan_id, state, stop_watching),
            name=f"scan-watcher-{claimed.scan_id}",
            daemon=True,
        )
        watcher.start()
        result: DiscoveryResult | None = None
        failure: _Failure | None = None
        try:
            # No session or transaction exists in this thread while scanning.
            result = self.runner(
                claimed.grant, claimed.config, cancel=state.token, on_event=events.append
            )
        except GrantRejected as exc:
            failure = _Failure(f"grant_{exc.code}", exc.message)
        except Exception as exc:
            # Never store exception text: it may contain target data. The
            # traceback goes to the worker log only.
            logger.exception("scanner failed for scan %s", claimed.scan_id)
            failure = _Failure("scanner_error", f"the scanner failed ({type(exc).__name__})")
        finally:
            stop_watching.set()
            watcher.join(timeout=self.heartbeat_interval + 5)
            self._current = None
        self.finalize(claimed, result, failure, state.cancel_reason)

    def _watch(self, scan_id: uuid.UUID, state: _RunState, stop: threading.Event) -> None:
        while not stop.wait(self.heartbeat_interval):
            try:
                reason = self._beat(scan_id)
            except Exception:
                logger.exception("heartbeat failed for scan %s", scan_id)
                continue
            if reason is not None:
                state.cancel(reason)

    def _beat(self, scan_id: uuid.UUID) -> str | None:
        """One short transaction: heartbeat, then decide whether the scan must
        stop. Returns a cancel reason or None."""
        with self.session_factory() as session:
            scan = ScanRepository(session).heartbeat(scan_id, self.worker_id)
            if scan is None:
                session.commit()
                return "ownership_lost"
            reason: str | None = None
            if scan.cancel_requested_at is not None:
                reason = scan.cancel_reason or "user_request"
            else:
                assessment = session.get(Assessment, scan.assessment_id)
                target = session.get(Target, scan.target_id)
                if assessment is None or assessment.status is not AssessmentStatus.IN_PROGRESS:
                    reason = f"assessment_{assessment.status if assessment else 'missing'}"
                elif target is None or target.current_authorization_id != scan.authorization_id:
                    reason = "authorization_superseded"
            session.commit()
            return reason

    # --- 3. finalize ----------------------------------------------------------------

    def finalize(
        self,
        claimed: ClaimedScan,
        result: DiscoveryResult | None,
        failure: _Failure | None,
        cancel_reason: str | None,
    ) -> bool:
        """Write results and the final status in one transaction. Returns False
        (and writes nothing) if this worker no longer owns the scan."""
        with self.session_factory() as session:
            scans = ScanRepository(session)
            repo = ScanResultRepository(session)
            scan = scans.get_for_update(claimed.scan_id)
            if (
                scan is None
                or scan.status is not ScanStatus.RUNNING
                or scan.claimed_by != self.worker_id
            ):
                logger.warning(
                    "discarding results for scan %s: no longer owned by %s",
                    claimed.scan_id,
                    self.worker_id,
                )
                return False

            now = self.clock()
            # Write all rows first, then change the scan in one step: the scan
            # row must never be flushed in a half-updated state (the database
            # checks that terminal statuses carry finished_at).
            if failure is not None or result is None:
                failure = failure or _Failure("scanner_error", "the scanner returned no result")
                logs = persist_logs(
                    repo,
                    scan.id,
                    [
                        claimed.claimed_at_log,
                        LogEntry(now, "warning", failure.code, failure.message),
                    ],
                )
                scan.status = ScanStatus.FAILED
                scan.error_code = failure.code
                scan.error_message = failure.message[:MAX_ERROR_MESSAGE]
                scan.events_count = logs
                scan.finished_at = now
            else:
                cancelled = result.stop_reason is StopReason.CANCELLED
                final_status = ScanStatus.CANCELLED if cancelled else ScanStatus.COMPLETED
                final_cancel_reason = scan.cancel_reason or (
                    (cancel_reason or "cancelled") if cancelled else None
                )
                counts = persist_discovery_result(
                    repo,
                    scan.id,
                    result,
                    before=[claimed.claimed_at_log],
                    after=[
                        LogEntry(
                            now,
                            "info",
                            f"scan_{final_status.value}",
                            f"scan {final_status.value} "
                            f"(scanner stop reason: {result.stop_reason})",
                            data={"cancel_reason": final_cancel_reason} if cancelled else None,
                        )
                    ],
                )
                if cancelled and scan.cancel_requested_at is None:
                    scan.cancel_requested_at = now
                scan.cancel_reason = final_cancel_reason
                scan.status = final_status
                scan.stop_reason = result.stop_reason.value if result.stop_reason else None
                scan.requests_sent = result.requests_sent
                scan.pages_count = len(result.pages)
                scan.endpoints_count = counts.endpoints
                scan.events_count = counts.logs
                scan.evidence_count = counts.evidence
                scan.finished_at = now
            session.commit()
            logger.info("scan %s finished: %s", scan.id, scan.status)
            return True

    # --- reaper ---------------------------------------------------------------------

    def reap_stale(self) -> int:
        with self.session_factory() as session:
            now = self.clock()
            reaped = ScanRepository(session).reap_stale(self.stale_after, now)
            repo = ScanResultRepository(session)
            for scan_id in reaped:
                persist_logs(
                    repo,
                    scan_id,
                    [
                        LogEntry(
                            now, "warning", "worker_lost", "the worker stopped sending heartbeats"
                        )
                    ],
                    start=10_000,  # after anything the lost worker might have written
                )
            session.commit()
        for scan_id in reaped:
            logger.warning("scan %s failed: worker_lost", scan_id)
        return len(reaped)
