"""The worker (ADR 0008, 0009, 0010).

Roles: `scans` runs scans and their analysis, `reports` renders reports, `all`
does both (local development). Compose runs one process per role, so a long
scan never delays a report and the PDF engine never runs in the scanning
process.

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
             write all results and the final status together, and queue the
             scan's analysis run (completed / cancelled scans); otherwise drop
             the results (e.g. the scan was reaped).

Analysis runs (ADR 0009) and retest comparisons (ADR 0011) are claimed with
SKIP LOCKED and executed entirely in one transaction: a crash rolls it back and
the job stays queued; an error raised while computing marks it failed (code
only). Neither has a running state, and neither contacts the target.

Reports (ADR 0010), in three phases like scans:

1. claim     short transaction: lock a queued report (SKIP LOCKED), mark it
             generating and read its frozen snapshot.
2. render    with NO session open: a pure function of the snapshot, the
             template version and the renderer version. No network.
3. finalize  one transaction: lock the report; if this worker still owns it,
             write the artifacts and complete it (or fail it with an error
             code only); otherwise discard the output (e.g. it was reaped).

A reaper fails reports left generating by a worker that stopped.

Retest reports (ADR 0012) use the same three phases and reaper, in the same
reports role, from their own table; Phase 5 reports are polled first.

No automatic retries: a failed scan or report stays failed.
"""

import logging
import threading
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from sentinel_analysis import RULESET_VERSION
from sqlalchemy import func
from sqlalchemy.orm import Session, sessionmaker

from app.core.audit import AuditAction
from app.core.authz import ResourceType
from app.core.clock import Clock, utc_now
from app.core.errors import ScanNotAllowedError
from app.models import Assessment, ReportArtifact, RetestReportArtifact, Target
from app.models.enums import (
    AnalysisStatus,
    AssessmentStatus,
    AuditOutcome,
    ComparisonStatus,
    ReportStatus,
    ScanStatus,
)
from app.repositories import (
    AnalysisRepository,
    AssessmentRepository,
    ComparisonRepository,
    QueuedCandidate,
    ReportRepository,
    RetestReportRepository,
    ScanRepository,
    ScanResultRepository,
    TargetRepository,
)
from app.services.analysis import AnalysisError, execute_run, fail_run
from app.services.audit import WORKER, AuditService
from app.services.comparisons import ComparisonError, execute_comparison, fail_comparison
from app.services.scan_grants import build_scan_grant, discovery_config, grant_snapshot
from app.services.scan_results import (
    LogEntry,
    persist_discovery_result,
    persist_logs,
)
from sentinel_reports import Artifact, ReportError, render_report
from sentinel_reports.retest import render_retest_report
from sentinel_scanner import CancellationToken, DiscoveryConfig, DiscoveryResult, run_discovery
from sentinel_scanner.errors import GrantRejected
from sentinel_scanner.grant import ScanGrant
from sentinel_scanner.models import ScanEvent, StopReason
from sentinel_scanner.version import __version__ as scanner_version

logger = logging.getLogger(__name__)

MAX_ERROR_MESSAGE = 1000


class WorkerRole(StrEnum):
    SCANS = "scans"  # scans and their analysis
    REPORTS = "reports"
    ALL = "all"  # local development


class ReportRenderer(Protocol):
    def __call__(
        self, snapshot: Mapping[str, Any], formats: Iterable[str]
    ) -> tuple[Artifact, ...]: ...


@dataclass(frozen=True)
class ClaimedReport:
    report_id: uuid.UUID
    snapshot: dict[str, Any]
    formats: tuple[str, ...]


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
        role: WorkerRole = WorkerRole.ALL,
        report_renderer: ReportRenderer = render_report,
        report_stale_after: float = 600.0,
        retest_report_renderer: ReportRenderer = render_retest_report,
    ) -> None:
        self.session_factory = session_factory
        self.role = role
        self.report_renderer = report_renderer
        self.report_stale_after = report_stale_after
        self.retest_report_renderer = retest_report_renderer
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

    @property
    def runs_scans(self) -> bool:
        return self.role in (WorkerRole.SCANS, WorkerRole.ALL)

    @property
    def runs_reports(self) -> bool:
        return self.role in (WorkerRole.REPORTS, WorkerRole.ALL)

    def run_once(self) -> bool:
        """Reap stale work of this worker's role, then do at most one unit of
        work: a queued analysis, else a queued report, else a scan."""
        if self.runs_scans:
            self.reap_stale()
        if self.runs_reports:
            self.reap_stale_reports()
            self.reap_stale_retest_reports()
        if self.runs_scans and self.analyze_once():
            return True
        if self.runs_scans and self.compare_once():
            return True
        if self.runs_reports and self.report_once():
            return True
        if self.runs_reports and self.retest_report_once():
            return True
        if not self.runs_scans:
            return False
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

    def _audit(
        self,
        session: Session,
        action: AuditAction,
        resource: tuple[ResourceType, uuid.UUID],
        *,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """A lifecycle event of this worker (a system actor named by its worker
        id; never the user who requested the work), in the same transaction as
        the transition it records."""
        AuditService(session, WORKER).system(
            action, self.worker_id, resource=resource, outcome=outcome, metadata=metadata
        )

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
                self._audit(
                    session,
                    AuditAction.SCAN_REFUSED,
                    (ResourceType.SCAN, scan.id),
                    outcome=AuditOutcome.DENIED,
                    metadata={"reason": exc.reason[:64]},
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
            self._audit(session, AuditAction.SCAN_STARTED, (ResourceType.SCAN, scan.id))
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
                # Same transaction as the results: a finalized scan always has
                # its analysis queued, and a dropped finalize queues nothing.
                AnalysisRepository(session).queue_run(scan.id, RULESET_VERSION)
            if scan.status is ScanStatus.COMPLETED:
                self._audit(
                    session,
                    AuditAction.SCAN_COMPLETED,
                    (ResourceType.SCAN, scan.id),
                    metadata={
                        "requests_sent": scan.requests_sent,
                        "endpoints_count": scan.endpoints_count,
                    },
                )
            elif scan.status is ScanStatus.CANCELLED:
                self._audit(session, AuditAction.SCAN_CANCELLED, (ResourceType.SCAN, scan.id))
            else:
                self._audit(
                    session,
                    AuditAction.SCAN_FAILED,
                    (ResourceType.SCAN, scan.id),
                    outcome=AuditOutcome.FAILURE,
                    metadata={"reason": (scan.error_code or "failed")[:64]},
                )
            session.commit()
            logger.info("scan %s finished: %s", scan.id, scan.status)
            return True

    # --- analysis -------------------------------------------------------------------

    def analyze_once(self) -> bool:
        """Run at most one queued analysis. Returns True if one was processed."""
        with self.session_factory() as session:
            run_ids = AnalysisRepository(session).queued_run_ids(self.candidate_batch)
        return any(self._try_analyze(run_id) for run_id in run_ids)

    def _try_analyze(self, run_id: uuid.UUID) -> bool:
        with self.session_factory() as session:
            repo = AnalysisRepository(session)
            run = repo.get_run_for_update(run_id, skip_locked=True)
            if run is None or run.status is not AnalysisStatus.QUEUED:
                return False  # another worker has it, or it is already done
            # The scan is terminal and no longer changes; it is read, not locked.
            scan = ScanRepository(session).get(run.scan_id)
            now = self.clock()
            try:
                with session.begin_nested():
                    execute_run(repo, scan, run, now)
            except Exception as exc:
                # Everything the run wrote is rolled back to the savepoint.
                # Only a code is stored: exception text may contain target data.
                code = exc.code if isinstance(exc, AnalysisError) else "analysis_error"
                if not isinstance(exc, AnalysisError):
                    logger.exception("analysis run %s failed", run_id)
                session.refresh(run)
                fail_run(run, code, now)
            if AnalysisStatus(run.status) is AnalysisStatus.COMPLETED:  # changed above
                self._audit(
                    session,
                    AuditAction.ANALYSIS_COMPLETED,
                    (ResourceType.ANALYSIS_RUN, run.id),
                    metadata={"scan_id": str(run.scan_id)},
                )
            else:
                self._audit(
                    session,
                    AuditAction.ANALYSIS_FAILED,
                    (ResourceType.ANALYSIS_RUN, run.id),
                    outcome=AuditOutcome.FAILURE,
                    metadata={"scan_id": str(run.scan_id)},
                )
            session.commit()
            logger.info("analysis run %s finished: %s", run_id, run.status)
            return True

    # --- comparisons -----------------------------------------------------------------

    def compare_once(self) -> bool:
        """Compute at most one queued comparison. Returns True if one was processed."""
        with self.session_factory() as session:
            ids = ComparisonRepository(session).queued_ids(self.candidate_batch)
        return any(self._try_compare(comparison_id) for comparison_id in ids)

    def _try_compare(self, comparison_id: uuid.UUID) -> bool:
        with self.session_factory() as session:
            repo = ComparisonRepository(session)
            comparison = repo.get_for_update(comparison_id, skip_locked=True)
            if comparison is None or comparison.status is not ComparisonStatus.QUEUED:
                return False  # another worker has it, or it is already done
            now = self.clock()
            try:
                with session.begin_nested():
                    execute_comparison(session, comparison, now)
            except Exception as exc:
                # Everything it wrote is rolled back to the savepoint. Only a
                # code is stored: exception text may contain target data.
                code = exc.code if isinstance(exc, ComparisonError) else "comparison_error"
                if not isinstance(exc, ComparisonError):
                    logger.exception("comparison %s failed", comparison_id)
                session.refresh(comparison)
                fail_comparison(comparison, code, now)
            if ComparisonStatus(comparison.status) is ComparisonStatus.COMPLETED:  # changed above
                self._audit(
                    session,
                    AuditAction.COMPARISON_COMPLETED,
                    (ResourceType.COMPARISON, comparison.id),
                )
            else:
                self._audit(
                    session,
                    AuditAction.COMPARISON_FAILED,
                    (ResourceType.COMPARISON, comparison.id),
                    outcome=AuditOutcome.FAILURE,
                    metadata={"reason": (comparison.error_code or "failed")[:64]},
                )
            session.commit()
            logger.info("comparison %s finished: %s", comparison_id, comparison.status)
            return True

    # --- reports ------------------------------------------------------------------

    def report_once(self) -> bool:
        """Generate at most one queued report. Returns True if one was processed."""
        with self.session_factory() as session:
            report_ids = ReportRepository(session).queued_ids(self.candidate_batch)
        for report_id in report_ids:
            claimed = self.claim_report(report_id)
            if claimed is not None:
                self.generate_report(claimed)
                return True
        return False

    def claim_report(self, report_id: uuid.UUID) -> ClaimedReport | None:
        with self.session_factory() as session:
            report = ReportRepository(session).get_for_update(report_id, skip_locked=True)
            if report is None or report.status is not ReportStatus.QUEUED:
                return None  # another worker has it, or it is no longer queued
            report.status = ReportStatus.GENERATING
            report.claimed_by = self.worker_id
            report.claimed_at = func.now()  # database clock, as the reaper uses
            claimed = ClaimedReport(report.id, dict(report.snapshot), tuple(report.formats))
            session.commit()
            logger.info("report %s claimed by %s", report_id, self.worker_id)
            return claimed

    def generate_report(self, claimed: ClaimedReport) -> None:
        artifacts: tuple[Artifact, ...] = ()
        error: str | None = None
        try:
            # No session or transaction exists here: rendering reads only the
            # frozen snapshot.
            artifacts = self.report_renderer(claimed.snapshot, claimed.formats)
        except ReportError as exc:
            error = exc.code
        except Exception:
            # Exception text could contain report data; the code is stored and
            # the traceback goes to the worker log only.
            logger.exception("report %s failed to render", claimed.report_id)
            error = "render_error"
        if error is None and sorted(a.format for a in artifacts) != sorted(claimed.formats):
            error = "render_error"
        self.finalize_report(claimed, artifacts, error)

    def finalize_report(
        self, claimed: ClaimedReport, artifacts: tuple[Artifact, ...], error: str | None
    ) -> bool:
        """Write the artifacts and the final status in one transaction. Returns
        False (and writes nothing) if this worker no longer owns the report."""
        with self.session_factory() as session:
            repo = ReportRepository(session)
            report = repo.get_for_update(claimed.report_id)
            if (
                report is None
                or report.status is not ReportStatus.GENERATING
                or report.claimed_by != self.worker_id
            ):
                logger.warning(
                    "discarding output for report %s: no longer owned by %s",
                    claimed.report_id,
                    self.worker_id,
                )
                return False
            now = self.clock()
            if error is None:
                # Artifacts are flushed while the report is still generating
                # (the database accepts artifacts only then), then it completes.
                for artifact in artifacts:
                    repo.add_artifact(
                        ReportArtifact(
                            report_id=report.id,
                            format=artifact.format,
                            media_type=artifact.media_type,
                            content=artifact.content,
                            size_bytes=artifact.size,
                            sha256=artifact.sha256,
                            renderer=artifact.renderer[:200],
                        )
                    )
                report.status = ReportStatus.COMPLETED
            else:
                report.status = ReportStatus.FAILED
                report.error_code = error[:64]
            report.finished_at = now
            self._report_event(
                session, ResourceType.REPORT, report.id, report.status, report.error_code
            )
            session.commit()
            logger.info("report %s finished: %s", claimed.report_id, report.status)
            return True

    def _report_event(
        self,
        session: Session,
        kind: ResourceType,
        report_id: uuid.UUID,
        status: ReportStatus,
        error_code: str | None,
    ) -> None:
        retest = kind is ResourceType.RETEST_REPORT
        if status is ReportStatus.COMPLETED:
            action = AuditAction.RETEST_REPORT_COMPLETED if retest else AuditAction.REPORT_COMPLETED
            self._audit(session, action, (kind, report_id))
        else:
            action = AuditAction.RETEST_REPORT_FAILED if retest else AuditAction.REPORT_FAILED
            self._audit(
                session,
                action,
                (kind, report_id),
                outcome=AuditOutcome.FAILURE,
                metadata={"reason": (error_code or "failed")[:64]},
            )

    def reap_stale_reports(self) -> int:
        with self.session_factory() as session:
            reaped = ReportRepository(session).reap_stale(self.report_stale_after, self.clock())
            for report_id in reaped:
                self._report_event(
                    session, ResourceType.REPORT, report_id, ReportStatus.FAILED, "worker_lost"
                )
            session.commit()
        for report_id in reaped:
            logger.warning("report %s failed: worker_lost", report_id)
        return len(reaped)

    # --- retest reports (ADR 0012) --------------------------------------------------------

    def retest_report_once(self) -> bool:
        """Generate at most one queued retest report."""
        with self.session_factory() as session:
            report_ids = RetestReportRepository(session).queued_ids(self.candidate_batch)
        for report_id in report_ids:
            claimed = self.claim_retest_report(report_id)
            if claimed is not None:
                self.generate_retest_report(claimed)
                return True
        return False

    def claim_retest_report(self, report_id: uuid.UUID) -> ClaimedReport | None:
        with self.session_factory() as session:
            report = RetestReportRepository(session).get_for_update(report_id, skip_locked=True)
            if report is None or report.status is not ReportStatus.QUEUED:
                return None
            report.status = ReportStatus.GENERATING
            report.claimed_by = self.worker_id
            report.claimed_at = func.now()  # database clock, as the reaper uses
            claimed = ClaimedReport(report.id, dict(report.snapshot), tuple(report.formats))
            session.commit()
            logger.info("retest report %s claimed by %s", report_id, self.worker_id)
            return claimed

    def generate_retest_report(self, claimed: ClaimedReport) -> None:
        artifacts: tuple[Artifact, ...] = ()
        error: str | None = None
        try:
            # No session or transaction exists here: rendering reads only the
            # frozen snapshot.
            artifacts = self.retest_report_renderer(claimed.snapshot, claimed.formats)
        except ReportError as exc:
            error = exc.code
        except Exception:
            logger.exception("retest report %s failed to render", claimed.report_id)
            error = "render_error"
        if error is None and sorted(a.format for a in artifacts) != sorted(claimed.formats):
            error = "render_error"
        self.finalize_retest_report(claimed, artifacts, error)

    def finalize_retest_report(
        self, claimed: ClaimedReport, artifacts: tuple[Artifact, ...], error: str | None
    ) -> bool:
        """Write the artifacts and the final status in one transaction. Returns
        False (and writes nothing) if this worker no longer owns the report."""
        with self.session_factory() as session:
            repo = RetestReportRepository(session)
            report = repo.get_for_update(claimed.report_id)
            if (
                report is None
                or report.status is not ReportStatus.GENERATING
                or report.claimed_by != self.worker_id
            ):
                logger.warning(
                    "discarding output for retest report %s: no longer owned by %s",
                    claimed.report_id,
                    self.worker_id,
                )
                return False
            now = self.clock()
            if error is None:
                for artifact in artifacts:
                    repo.add_artifact(
                        RetestReportArtifact(
                            report_id=report.id,
                            format=artifact.format,
                            media_type=artifact.media_type,
                            content=artifact.content,
                            size_bytes=artifact.size,
                            sha256=artifact.sha256,
                            renderer=artifact.renderer[:200],
                        )
                    )
                report.status = ReportStatus.COMPLETED
            else:
                report.status = ReportStatus.FAILED
                report.error_code = error[:64]
            report.finished_at = now
            self._report_event(
                session, ResourceType.RETEST_REPORT, report.id, report.status, report.error_code
            )
            session.commit()
            logger.info("retest report %s finished: %s", claimed.report_id, report.status)
            return True

    def reap_stale_retest_reports(self) -> int:
        with self.session_factory() as session:
            reaped = RetestReportRepository(session).reap_stale(
                self.report_stale_after, self.clock()
            )
            for report_id in reaped:
                self._report_event(
                    session,
                    ResourceType.RETEST_REPORT,
                    report_id,
                    ReportStatus.FAILED,
                    "worker_lost",
                )
            session.commit()
        for report_id in reaped:
            logger.warning("retest report %s failed: worker_lost", report_id)
        return len(reaped)

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
                self._audit(
                    session,
                    AuditAction.SCAN_FAILED,
                    (ResourceType.SCAN, scan_id),
                    outcome=AuditOutcome.FAILURE,
                    metadata={"reason": "worker_lost"},
                )
            session.commit()
        for scan_id in reaped:
            logger.warning("scan %s failed: worker_lost", scan_id)
        return len(reaped)
