"""Worker behaviour with real PostgreSQL and a 127.0.0.1 lab site."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, text

from app.models.enums import ScanStatus
from sentinel_scanner import CancellationToken, DiscoveryConfig, ScanLimits
from sentinel_scanner.errors import GrantRejected
from sentinel_scanner.grant import ScanGrant
from tests.integration.scan_support import ScanEnv, lab_runner

pytestmark = pytest.mark.integration

SECRETS = ("LAB-SESSION-SECRET", "LAB-CSRF-SECRET")


def test_successful_scan_end_to_end(scan_env: ScanEnv) -> None:
    target_id, assessment_id, scan_id = scan_env.queued_scan()
    worker = scan_env.worker()

    assert worker.run_once() is True
    scan = scan_env.get_scan(scan_id)

    assert scan.status is ScanStatus.COMPLETED
    assert scan.stop_reason == "completed"
    assert scan.claimed_by == "worker-a"
    assert scan.started_at is not None and scan.finished_at is not None
    assert scan.error_code is None
    assert scan.requests_sent == len(scan_env.site.requests) > 0
    assert scan.endpoints_count == scan_env.count("endpoints", scan_id) > 0
    assert scan.evidence_count == scan_env.count("evidence", scan_id) == scan.pages_count
    assert scan.events_count == scan_env.count("scan_logs", scan_id)

    # The audit snapshot reflects the authorization record, not client input.
    snapshot = scan.grant_snapshot
    assert snapshot is not None
    assert snapshot["target_id"] == str(target_id)
    assert snapshot["assessment_id"] == str(assessment_id)
    assert snapshot["authorization_id"] == str(scan.authorization_id)
    assert snapshot["scope"]["in_scope_hosts"] == ["lab.test"]
    assert snapshot["scope"]["excluded_paths"] == ["/admin"]
    assert scan.scanner_version

    # Only safe, in-scope requests reached the site.
    assert {m for m, _ in scan_env.site.requests} <= {"GET", "OPTIONS"}
    paths = {p for _, p in scan_env.site.requests}
    assert {"/", "/about"} <= paths
    assert not paths & {"/admin", "/logout", "/login"}

    # Logs: worker entries around the scanner's events, numbered 1..n.
    with scan_env.factory() as s:
        codes = s.scalars(
            text("SELECT code FROM scan_logs WHERE scan_id = :s ORDER BY sequence"), {"s": scan_id}
        ).all()
        sequences = s.scalars(
            text("SELECT sequence FROM scan_logs WHERE scan_id = :s ORDER BY sequence"),
            {"s": scan_id},
        ).all()
    assert codes[0] == "scan_claimed" and codes[-1] == "scan_completed"
    assert "scan_started" in codes and "scan_finished" in codes
    assert list(sequences) == list(range(1, len(sequences) + 1))


def test_persisted_results_stay_redacted(scan_env: ScanEnv) -> None:
    _, _, scan_id = scan_env.queued_scan()
    scan_env.worker().run_once()
    dump = scan_env.all_text(scan_id)
    assert dump  # something was persisted
    for secret in SECRETS:
        assert secret not in dump
    with scan_env.factory() as s:
        cookies = s.execute(
            text(
                "SELECT DISTINCT c.name, c.http_only, c.secure FROM endpoint_cookies c "
                "JOIN endpoints e ON e.id = c.endpoint_id WHERE e.scan_id = :s"
            ),
            {"s": scan_id},
        ).all()
    # Set on both the GET and OPTIONS responses for "/"; flags only, no value.
    assert [tuple(c) for c in cookies] == [("SESSIONID", True, False)]


def test_scanner_runs_with_no_database_connection_held(scan_env: ScanEnv, engine: Engine) -> None:
    seen: dict[str, Any] = {}

    def hook(grant: ScanGrant, config: DiscoveryConfig) -> None:
        seen["checked_out"] = engine.pool.checkedout()  # type: ignore[attr-defined]
        seen["grant"] = grant
        seen["config"] = config

    _, _, scan_id = scan_env.queued_scan()
    scan_env.worker(runner=lab_runner(hook=hook)).run_once()

    assert seen["checked_out"] == 0
    assert isinstance(seen["grant"], ScanGrant)
    assert isinstance(seen["config"], DiscoveryConfig)
    # Limits are the scanner defaults; they are never taken from stored data.
    assert seen["config"].limits == ScanLimits()
    assert seen["config"].verify_tls is True
    assert scan_env.get_scan(scan_id).status is ScanStatus.COMPLETED


def test_allow_untrusted_tls_is_the_only_override(scan_env: ScanEnv) -> None:
    seen: dict[str, Any] = {}
    target_id = scan_env.target()
    assessment_id = scan_env.started_assessment(target_id)
    scan_id = scan_env.scan(assessment_id, allow_untrusted_tls=True)
    # Tampering with the stored limits must have no effect.
    with scan_env.factory() as s:
        s.execute(
            text(
                "UPDATE scans SET config = jsonb_set(config, '{limits,max_requests}', '100000') "
                "WHERE id = :s"
            ),
            {"s": scan_id},
        )
        s.commit()

    def hook(grant: ScanGrant, config: DiscoveryConfig) -> None:
        seen["config"] = config

    scan_env.worker(runner=lab_runner(hook=hook)).run_once()
    assert seen["config"].verify_tls is False
    assert seen["config"].limits == ScanLimits()


def test_scanner_exception_is_sanitized(scan_env: ScanEnv) -> None:
    def failing(grant: ScanGrant, config: DiscoveryConfig, **_: Any) -> Any:
        raise RuntimeError("boom: token=LAB-SESSION-SECRET at http://lab.test/private")

    _, _, scan_id = scan_env.queued_scan()
    scan_env.worker(runner=failing).run_once()
    scan = scan_env.get_scan(scan_id)

    assert scan.status is ScanStatus.FAILED
    assert scan.error_code == "scanner_error"
    assert scan.error_message == "the scanner failed (RuntimeError)"
    assert scan.finished_at is not None
    dump = scan_env.all_text(scan_id)
    assert "LAB-SESSION-SECRET" not in dump
    assert "/private" not in dump


def test_scanner_refusing_the_grant_fails_the_scan(scan_env: ScanEnv) -> None:
    def refusing(grant: ScanGrant, config: DiscoveryConfig, **_: Any) -> Any:
        raise GrantRejected("authorization_not_active", "authorization is expired")

    _, _, scan_id = scan_env.queued_scan()
    scan_env.worker(runner=refusing).run_once()
    scan = scan_env.get_scan(scan_id)
    assert scan.status is ScanStatus.FAILED
    assert scan.error_code == "grant_authorization_not_active"


def test_claim_rebuilds_the_grant_and_refuses_superseded_authorization(
    scan_env: ScanEnv,
) -> None:
    target_id, _, scan_id = scan_env.queued_scan()
    scan_env.reauthorize(target_id, reference="LAB-RENEWED")

    worker = scan_env.worker()
    assert worker.claim() is None
    scan = scan_env.get_scan(scan_id)
    assert scan.status is ScanStatus.FAILED
    assert scan.error_code == "authorization_superseded"
    assert scan.started_at is None
    assert scan.grant_snapshot is None
    assert scan_env.site.requests == []


def test_claim_refuses_expired_authorization(scan_env: ScanEnv) -> None:
    _, _, scan_id = scan_env.queued_scan()
    later = datetime.now(UTC) + timedelta(hours=2)  # past valid_until
    worker = scan_env.worker(clock=lambda: later)
    assert worker.claim() is None
    scan = scan_env.get_scan(scan_id)
    assert scan.status is ScanStatus.FAILED
    assert scan.error_code == "authorization_not_active"
    assert scan_env.site.requests == []


def test_cancelling_the_assessment_cancels_queued_scans(scan_env: ScanEnv) -> None:
    _, assessment_id, scan_id = scan_env.queued_scan()
    scan_env.cancel_assessment(assessment_id)
    scan = scan_env.get_scan(scan_id)
    assert scan.status is ScanStatus.CANCELLED
    assert scan.cancel_reason == "assessment_cancelled"
    assert scan_env.worker().claim() is None


def test_reaper_fails_stale_scans_and_late_results_are_discarded(scan_env: ScanEnv) -> None:
    _, _, scan_id = scan_env.queued_scan()
    lost = scan_env.worker("worker-lost")
    claimed = lost.claim()
    assert claimed is not None
    with scan_env.factory() as s:
        s.execute(
            text("UPDATE scans SET heartbeat_at = now() - interval '5 minutes' WHERE id = :s"),
            {"s": scan_id},
        )
        s.commit()

    assert scan_env.worker("worker-reaper", stale_after=60).reap_stale() == 1
    scan = scan_env.get_scan(scan_id)
    assert scan.status is ScanStatus.FAILED
    assert scan.error_code == "worker_lost"

    # The lost worker comes back and tries to finalize: nothing is written.
    result = lab_runner()(
        claimed.grant, claimed.config, cancel=CancellationToken(), on_event=lambda _: None
    )
    assert lost.finalize(claimed, result, None, None) is False
    assert scan_env.count("endpoints", scan_id) == 0
    assert scan_env.count("evidence", scan_id) == 0
    assert scan_env.get_scan(scan_id).status is ScanStatus.FAILED


def test_healthy_scans_are_not_reaped(scan_env: ScanEnv) -> None:
    _, _, scan_id = scan_env.queued_scan()
    assert scan_env.worker().claim() is not None
    assert scan_env.worker("worker-reaper", stale_after=60).reap_stale() == 0
    assert scan_env.get_scan(scan_id).status is ScanStatus.RUNNING


def test_duplicate_finalization_creates_no_duplicates(scan_env: ScanEnv) -> None:
    _, _, scan_id = scan_env.queued_scan()
    worker = scan_env.worker()
    claimed = worker.claim()
    assert claimed is not None
    result = lab_runner()(
        claimed.grant, claimed.config, cancel=CancellationToken(), on_event=lambda _: None
    )
    assert worker.finalize(claimed, result, None, None) is True
    counts = {
        t: scan_env.count(t, scan_id)
        for t in ("endpoints", "evidence", "assets", "scan_logs", "endpoint_cookies")
    }
    assert worker.finalize(claimed, result, None, None) is False  # no longer running
    assert {t: scan_env.count(t, scan_id) for t in counts} == counts


def test_failed_scans_are_not_retried(scan_env: ScanEnv) -> None:
    def failing(grant: ScanGrant, config: DiscoveryConfig, **_: Any) -> Any:
        raise RuntimeError("down")

    _, _, scan_id = scan_env.queued_scan()
    scan_env.worker(runner=failing).run_once()
    assert scan_env.worker().run_once() is False
    assert scan_env.get_scan(scan_id).status is ScanStatus.FAILED


def test_worker_shutdown_cancels_the_running_scan(scan_env: ScanEnv) -> None:
    scan_env.site.slow_site(pages=20, delay_s=0.1)
    _, _, scan_id = scan_env.queued_scan()
    holder: dict[str, Any] = {}

    def hook(grant: ScanGrant, config: DiscoveryConfig) -> None:
        holder["worker"].request_shutdown()

    worker = scan_env.worker(runner=lab_runner(hook=hook))
    holder["worker"] = worker
    worker.run_once()
    scan = scan_env.get_scan(scan_id)
    assert scan.status is ScanStatus.CANCELLED
    assert scan.cancel_reason == "worker_shutdown"
    assert scan.stop_reason == "cancelled"
