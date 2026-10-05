"""Scan races with real threads, real PostgreSQL commits and real locks."""

import functools
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.exc import IntegrityError

from app.api.deps import get_scan_service
from app.core.clock import utc_now
from app.core.errors import ScanNotAllowedError
from app.models.enums import ScanStatus
from app.repositories import ScanRepository
from app.services.scans import ScanService
from sentinel_scanner import DiscoveryConfig
from sentinel_scanner.grant import ScanGrant
from tests.integration.scan_support import ScanEnv, lab_runner

pytestmark = pytest.mark.integration

TIMEOUT = 20.0


class Outcome:
    def __init__(self) -> None:
        self.value: Any = None
        self.error: BaseException | None = None
        self.finished_at = 0.0


def start(fn: Callable[[], Any]) -> tuple[threading.Thread, Outcome]:
    outcome = Outcome()

    def run() -> None:
        try:
            outcome.value = fn()
        except BaseException as exc:  # asserted on by the test
            outcome.error = exc
        outcome.finished_at = time.monotonic()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, outcome


def pausing_clock(reached: threading.Event, pause: float = 0.5) -> Callable[[], datetime]:
    """A clock that signals and then waits the first time it is read: the
    worker's claim reads it while holding its locks."""
    state = {"paused": False}

    def clock() -> datetime:
        if not state["paused"]:
            state["paused"] = True
            reached.set()
            time.sleep(pause)
        return datetime.now(UTC)

    return clock


# --- Claiming ------------------------------------------------------------------------


def test_two_workers_cannot_claim_the_same_scan(scan_env: ScanEnv) -> None:
    _, _, scan_id = scan_env.queued_scan()
    barrier = threading.Barrier(2)
    workers = [scan_env.worker("worker-1"), scan_env.worker("worker-2")]

    def claim(worker: Any) -> Any:
        barrier.wait()
        return worker.claim()

    threads = [start(functools.partial(claim, w)) for w in workers]
    for thread, _ in threads:
        thread.join(TIMEOUT)

    claims = [o.value for _, o in threads if o.value is not None]
    assert [o.error for _, o in threads] == [None, None]
    assert len(claims) == 1
    scan = scan_env.get_scan(scan_id)
    assert scan.status is ScanStatus.RUNNING
    assert scan.claimed_by in {"worker-1", "worker-2"}


def test_many_workers_claim_each_scan_exactly_once(scan_env: ScanEnv) -> None:
    scan_ids = {scan_env.queued_scan()[2] for _ in range(3)}
    barrier = threading.Barrier(5)
    workers = [scan_env.worker(f"worker-{i}") for i in range(5)]

    def claim(worker: Any) -> Any:
        barrier.wait()
        return worker.claim()

    threads = [start(functools.partial(claim, w)) for w in workers]
    for thread, _ in threads:
        thread.join(TIMEOUT)
    claimed = [o.value.scan_id for _, o in threads if o.value is not None]
    assert sorted(map(str, claimed)) == sorted(map(str, scan_ids))
    assert len(set(claimed)) == len(claimed)


def test_cancel_waits_for_an_in_progress_claim(scan_env: ScanEnv) -> None:
    """The claim holds the scan lock; the cancel queues behind it and then
    requests cancellation of the now-running scan."""
    _, _, scan_id = scan_env.queued_scan()
    claim_holds_locks = threading.Event()
    worker = scan_env.worker(clock=pausing_clock(claim_holds_locks))

    claim_thread, claim = start(worker.claim)
    assert claim_holds_locks.wait(TIMEOUT)
    cancel_thread, cancel = start(lambda: scan_env.cancel_scan(scan_id))
    claim_thread.join(TIMEOUT)
    cancel_thread.join(TIMEOUT)

    assert claim.error is None and claim.value is not None
    assert cancel.error is None
    assert cancel.finished_at >= claim.finished_at
    scan = scan_env.get_scan(scan_id)
    assert scan.status is ScanStatus.RUNNING
    assert scan.cancel_requested_at is not None


def test_claim_skips_a_scan_being_cancelled(scan_env: ScanEnv) -> None:
    """The cancel holds the scan lock; the claim skips it (SKIP LOCKED) and
    the scan ends cancelled, never running."""
    _, _, scan_id = scan_env.queued_scan()
    cancel_holds_lock = threading.Event()

    class PausingCommit:
        def __init__(self, session: Any) -> None:
            self.session = session

        def commit(self) -> None:
            cancel_holds_lock.set()
            time.sleep(0.5)
            self.session.commit()

    def cancel() -> None:
        with scan_env.factory() as s:
            service = get_scan_service(s, utc_now)
            ScanService(
                service.scans,
                service.results,
                service.assessments,
                service.targets,
                PausingCommit(s),
                utc_now,
            ).cancel(scan_id, actor=scan_env.actor)

    cancel_thread, cancelled = start(cancel)
    assert cancel_holds_lock.wait(TIMEOUT)
    claim_thread, claim = start(scan_env.worker().claim)
    claim_thread.join(TIMEOUT)
    cancel_thread.join(TIMEOUT)

    assert cancelled.error is None
    assert claim.error is None and claim.value is None
    assert scan_env.get_scan(scan_id).status is ScanStatus.CANCELLED
    assert scan_env.worker().claim() is None
    assert scan_env.site.requests == []


# --- Creation ------------------------------------------------------------------------


def test_concurrent_scan_requests_create_one_scan(scan_env: ScanEnv) -> None:
    target_id = scan_env.target()
    assessment_id = scan_env.started_assessment(target_id)
    barrier = threading.Barrier(2)

    def create() -> Any:
        barrier.wait()
        return scan_env.scan(assessment_id)

    threads = [start(create) for _ in range(2)]
    for thread, _ in threads:
        thread.join(TIMEOUT)
    outcomes = [o for _, o in threads]
    assert sum(o.error is None for o in outcomes) == 1
    [refused] = [o.error for o in outcomes if o.error is not None]
    assert isinstance(refused, ScanNotAllowedError)
    assert refused.reason == "active_scan_exists"


def test_database_blocks_duplicate_active_scans_if_the_check_is_bypassed(
    scan_env: ScanEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_id = scan_env.target()
    assessment_id = scan_env.started_assessment(target_id)
    scan_env.scan(assessment_id)
    monkeypatch.setattr(ScanRepository, "has_active", lambda *_: False)
    with pytest.raises(IntegrityError, match="uq_scans_one_active_per_assessment"):
        scan_env.scan(assessment_id)


# --- During a scan -------------------------------------------------------------------


def slow_scan(scan_env: ScanEnv, **target_kwargs: Any) -> tuple[Any, Any, Any]:
    """A queued scan of a 40-page site where each page takes 0.15s."""
    scan_env.site.slow_site(pages=40, delay_s=0.15)
    target_id = scan_env.target(**target_kwargs)
    assessment_id = scan_env.started_assessment(target_id)
    return target_id, assessment_id, scan_env.scan(assessment_id)


def run_while(scan_env: ScanEnv, during: Callable[[], None] | None, **worker_kwargs: Any) -> None:
    """Run one worker iteration; call `during` once the scanner is making
    requests. The watcher beats every 0.1s."""
    scanning = threading.Event()
    worker = scan_env.worker(
        runner=lab_runner(hook=lambda g, c: scanning.set()),
        heartbeat_interval=0.1,
        **worker_kwargs,
    )
    thread, outcome = start(worker.run_once)
    assert scanning.wait(TIMEOUT)
    if during is not None:
        time.sleep(0.3)  # let it make some requests first
        during()
    thread.join(TIMEOUT * 2)
    assert not thread.is_alive()
    assert outcome.error is None, outcome.error


def test_user_cancel_during_a_scan(scan_env: ScanEnv) -> None:
    _, _, scan_id = slow_scan(scan_env)
    run_while(scan_env, lambda: scan_env.cancel_scan(scan_id))

    scan = scan_env.get_scan(scan_id)
    assert scan.status is ScanStatus.CANCELLED
    assert scan.stop_reason == "cancelled"
    assert scan.cancel_reason == "user_request"
    assert 0 < scan.pages_count < 40  # partial results are kept
    assert scan_env.count("endpoints", scan_id) > 0


def test_reauthorization_during_a_scan_cancels_it(scan_env: ScanEnv) -> None:
    target_id, _, scan_id = slow_scan(scan_env)
    run_while(scan_env, lambda: scan_env.reauthorize(target_id, reference="RENEWED"))

    scan = scan_env.get_scan(scan_id)
    assert scan.status is ScanStatus.CANCELLED
    assert scan.cancel_reason == "authorization_superseded"
    assert scan.pages_count < 40


def test_assessment_cancellation_during_a_scan_cancels_it(scan_env: ScanEnv) -> None:
    _, assessment_id, scan_id = slow_scan(scan_env)
    run_while(scan_env, lambda: scan_env.cancel_assessment(assessment_id))

    scan = scan_env.get_scan(scan_id)
    assert scan.status is ScanStatus.CANCELLED
    assert scan.cancel_reason == "assessment_cancelled"
    assert scan.pages_count < 40


def test_authorization_expiry_during_a_scan_stops_it(scan_env: ScanEnv) -> None:
    now = datetime.now(UTC)
    _, _, scan_id = slow_scan(
        scan_env,
        valid_from=(now - timedelta(hours=1)).isoformat(),
        valid_until=(now + timedelta(seconds=2.5)).isoformat(),
    )
    run_while(scan_env, None)

    scan = scan_env.get_scan(scan_id)
    # The scanner itself refuses requests after valid_until: the scan ends
    # normally with partial results, recording why it stopped.
    assert scan.status is ScanStatus.COMPLETED
    assert scan.stop_reason == "authorization_expired"
    assert 0 < scan.pages_count < 40


def test_scan_that_finishes_while_cancel_is_requested_stays_completed(
    scan_env: ScanEnv,
) -> None:
    """The cancel arrives after the scanner has finished but before finalize:
    the scan really did complete, and the request is still recorded."""
    _, _, scan_id = scan_env.queued_scan()
    inner = lab_runner()

    def runner(grant: ScanGrant, config: DiscoveryConfig, **kwargs: Any) -> Any:
        result = inner(grant, config, **kwargs)
        scan_env.cancel_scan(scan_id)  # arrives late
        return result

    scan_env.worker(runner=runner).run_once()
    scan = scan_env.get_scan(scan_id)
    assert scan.status is ScanStatus.COMPLETED
    assert scan.stop_reason == "completed"
    assert scan.cancel_requested_at is not None
    assert scan.cancel_reason == "user_request"


def test_cancel_of_a_finished_scan_is_refused(scan_env: ScanEnv) -> None:
    _, _, scan_id = scan_env.queued_scan()
    scan_env.worker().run_once()
    with pytest.raises(Exception, match="cannot be cancelled"):
        scan_env.cancel_scan(scan_id)
    assert scan_env.get_scan(scan_id).status is ScanStatus.COMPLETED


def test_completing_the_assessment_is_refused_while_a_scan_runs(scan_env: ScanEnv) -> None:
    from app.api.deps import get_assessment_service

    _, assessment_id, scan_id = scan_env.queued_scan()
    with scan_env.factory() as s, pytest.raises(Exception, match="queued or running scan"):
        get_assessment_service(s, utc_now).complete(assessment_id, actor=scan_env.actor)
    scan_env.worker().run_once()
    with scan_env.factory() as s:
        get_assessment_service(s, utc_now).complete(assessment_id, actor=scan_env.actor)
    assert scan_env.get_scan(scan_id).status is ScanStatus.COMPLETED
