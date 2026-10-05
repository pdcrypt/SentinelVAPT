"""Phase 4 analysis through the real worker against a 127.0.0.1 lab site.

Covers: the golden end-to-end scan -> analysis -> findings result, run
queueing, idempotency, crash / failure / rule-error handling, concurrency, the
TLS certificate-verification contract, and secret leakage.
"""

import threading
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sentinel_analysis import RULESET_VERSION, analyze
from sentinel_analysis.rules.base import Rule
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.api.deps import get_principal
from app.core.config import Settings
from app.db.session import get_session
from app.main import create_app
from app.models import AnalysisRun, Finding, FindingEvidence, ProjectMember, Scan, User
from app.models.enums import AnalysisStatus, ProjectRole, ScanStatus
from app.repositories import AnalysisRepository
from app.services import analysis as analysis_service
from app.worker import core as worker_core
from sentinel_scanner import CancellationToken, DiscoveryConfig, DiscoveryResult, ScanLimits
from sentinel_scanner import run_discovery as real_run_discovery
from sentinel_scanner.grant import ScanGrant
from sentinel_scanner.models import ScanEvent
from tests.integration.conftest import principal_for
from tests.integration.lab_site import LabSite
from tests.integration.scan_support import RESOLVER, ScanEnv
from tests.integration.tls_support import self_signed_server_context

pytestmark = pytest.mark.integration

SESSION_SECRET = "GOLDEN-SESSION-SECRET"  # noqa: S105  # lab fixture value, must never be stored


def golden_site(site: LabSite) -> None:
    """One weakness per rule that can fire on a plain-HTTP lab site."""
    site.pages.clear()
    site.html(
        "/",
        "<title>Golden</title>"
        '<a href="/about">About</a><a href="/error">Error</a><a href="/files/">Files</a>',
        headers=[
            ("Server", "nginx/1.25.3"),
            ("X-Powered-By", "PHP/8.2.1"),
            ("Set-Cookie", f"SESSIONID={SESSION_SECRET}; Path=/"),
            ("Set-Cookie", "theme=dark; Path=/; SameSite=Lax"),
            ("Allow", "GET, HEAD, OPTIONS, PUT, DELETE"),
        ],
    )
    site.html(
        "/about",
        "<title>About</title>",
        headers=[
            ("Access-Control-Allow-Origin", "*"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ],
    )
    site.html(
        "/error",
        "<title>Error</title><pre>Traceback (most recent call last):\n"
        '  File "/srv/app.py", line 1</pre>',
        status=500,
    )
    site.html("/files/", "<title>Index of /files/</title><a href='a.txt'>a.txt</a>")


def scan_and_analyse(env: ScanEnv, **scan_kwargs: Any) -> uuid.UUID:
    target_id = env.target()
    assessment_id = env.started_assessment(target_id)
    scan_id = env.scan(assessment_id, **scan_kwargs)
    worker = env.worker()
    assert worker.run_once()  # the scan
    assert worker.run_once()  # its analysis
    return scan_id


def findings_of(env: ScanEnv, scan_id: uuid.UUID) -> list[Finding]:
    with env.factory() as s:
        rows = s.scalars(
            select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.rule_id)
        ).all()
        s.expunge_all()
        return list(rows)


def run_of(env: ScanEnv, scan_id: uuid.UUID) -> AnalysisRun:
    with env.factory() as s:
        run = s.scalars(select(AnalysisRun).where(AnalysisRun.scan_id == scan_id)).one()
        s.expunge(run)
        return run


@pytest.fixture
def committed_api(settings: Settings, scan_env: ScanEnv) -> Iterator[TestClient]:
    """API client whose requests commit to the database the worker uses. It
    acts as a committed user who owns the scan_env project (see the `api`
    fixture for why the principal is overridden)."""
    with scan_env.factory() as s:
        user = User(username=f"api-{uuid.uuid4().hex[:12]}", display_name="API Tester")
        s.add(user)
        s.flush()
        s.add(
            ProjectMember(project_id=scan_env.project_id, user_id=user.id, role=ProjectRole.OWNER)
        )
        s.commit()
        s.expunge(user)
    app = create_app(settings)
    app.dependency_overrides[get_principal] = lambda: principal_for(user)

    def session() -> Iterator[Session]:
        with scan_env.factory() as s:
            yield s

    app.dependency_overrides[get_session] = session
    try:
        with TestClient(app) as client:
            yield client
    finally:
        with scan_env.factory() as s:
            # Test cleanup only: users cannot be deleted normally and the
            # project would otherwise be left without an owner.
            s.execute(text("SET LOCAL session_replication_role = replica"))
            s.execute(text("DELETE FROM project_members WHERE user_id = :u"), {"u": user.id})
            s.execute(text("DELETE FROM users WHERE id = :u"), {"u": user.id})
            s.commit()


# --- golden end-to-end ------------------------------------------------------------------


def test_golden_scan_produces_exactly_the_expected_findings(scan_env: ScanEnv) -> None:
    golden_site(scan_env.site)
    scan_id = scan_and_analyse(scan_env)
    origin = f"http://lab.test:{scan_env.site.port}"

    run = run_of(scan_env, scan_id)
    assert run.status is AnalysisStatus.COMPLETED
    assert run.ruleset_version == RULESET_VERSION
    assert run.rule_errors == []
    assert run.coverage_notes == []
    assert run.rules_evaluated == 14

    found = {(f.rule_id, f.subject_key, f.discriminator) for f in findings_of(scan_env, scan_id)}
    assert found == {
        ("SV-TRN-001", origin, ""),
        ("SV-HDR-002", origin, ""),
        ("SV-HDR-003", origin, ""),
        ("SV-HDR-004", origin, ""),
        ("SV-CKE-001", origin, "SESSIONID"),
        ("SV-CKE-003", origin, "SESSIONID"),
        ("SV-INF-001", origin, "server"),
        ("SV-INF-001", origin, "x-powered-by"),
        ("SV-INF-002", f"GET {origin}/error", ""),
        ("SV-INF-003", f"GET {origin}/files/", ""),
        ("SV-COR-001", origin, ""),
        ("SV-MTH-001", f"OPTIONS {origin}/", ""),
    }
    assert run.findings_count == len(found)

    findings = findings_of(scan_env, scan_id)
    with scan_env.factory() as s:
        for finding in findings:
            assert finding.severity in ("low", "informational")
            assert finding.origin == "rule"
            assert finding.status == "open"
            links = s.scalars(
                select(FindingEvidence).where(FindingEvidence.finding_id == finding.id)
            ).all()
            assert 1 <= len(links) <= 25, finding.rule_id
            assert all(link.scan_id == scan_id for link in links)
            if finding.subject_type == "origin":
                assert finding.asset_id is not None
            else:
                assert finding.endpoint_id is not None


def test_fingerprints_are_stable_across_scans(scan_env: ScanEnv) -> None:
    golden_site(scan_env.site)
    first = scan_and_analyse(scan_env)
    second = scan_and_analyse(scan_env)
    a = {f.fingerprint for f in findings_of(scan_env, first)}
    b = {f.fingerprint for f in findings_of(scan_env, second)}
    assert a and a == b


def test_no_secret_reaches_findings_or_runs(scan_env: ScanEnv) -> None:
    golden_site(scan_env.site)
    scan_id = scan_and_analyse(scan_env)
    stored = scan_env.all_text(scan_id)
    assert "SV-CKE-001" in stored  # the findings are part of the checked text
    assert SESSION_SECRET not in stored


def test_findings_reference_evidence_instead_of_copying_bodies(scan_env: ScanEnv) -> None:
    golden_site(scan_env.site)
    scan_id = scan_and_analyse(scan_env)
    for finding in findings_of(scan_env, scan_id):
        assert "Traceback" not in str(finding.details)
        assert len(str(finding.details)) < 4000


# --- queueing --------------------------------------------------------------------------


def test_finalize_queues_one_run_for_a_completed_scan(scan_env: ScanEnv) -> None:
    _, _, scan_id = scan_env.queued_scan()
    worker = scan_env.worker()
    assert worker.run_once()
    run = run_of(scan_env, scan_id)
    assert run.status is AnalysisStatus.QUEUED
    assert run.ruleset_version == RULESET_VERSION
    assert worker.run_once()
    assert run_of(scan_env, scan_id).status is AnalysisStatus.COMPLETED
    assert not worker.run_once()  # nothing left


def test_failed_scans_are_not_analysed(scan_env: ScanEnv) -> None:
    def broken(*_: Any, **__: Any) -> DiscoveryResult:
        raise RuntimeError("boom")

    _, _, scan_id = scan_env.queued_scan()
    assert scan_env.worker(runner=broken).run_once()
    assert scan_env.get_scan(scan_id).status is ScanStatus.FAILED
    assert scan_env.count("analysis_runs", scan_id) == 0


def test_cancelled_scan_is_analysed_with_partial_coverage(scan_env: ScanEnv) -> None:
    def cancelled_runner(
        grant: ScanGrant,
        config: DiscoveryConfig,
        *,
        cancel: CancellationToken,
        on_event: Callable[[ScanEvent], None],
    ) -> DiscoveryResult:
        cancel.cancel()
        return real_run_discovery(
            grant,
            DiscoveryConfig(limits=ScanLimits(max_requests_per_second=20)),
            cancel=cancel,
            on_event=on_event,
            resolver=RESOLVER,
        )

    _, _, scan_id = scan_env.queued_scan()
    worker = scan_env.worker(runner=cancelled_runner)
    assert worker.run_once()
    assert scan_env.get_scan(scan_id).status is ScanStatus.CANCELLED
    assert worker.run_once()
    run = run_of(scan_env, scan_id)
    assert run.status is AnalysisStatus.COMPLETED
    assert "partial_scan" in run.coverage_notes


# --- idempotency, failure and crash handling ------------------------------------------


def test_persisting_the_same_result_twice_changes_nothing(scan_env: ScanEnv) -> None:
    golden_site(scan_env.site)
    scan_id = scan_and_analyse(scan_env)
    before = (scan_env.count("findings", scan_id), _links(scan_env, scan_id))
    with scan_env.factory() as s:
        repo = AnalysisRepository(s)
        scan = s.get(Scan, scan_id)
        assert scan is not None
        run = s.scalars(select(AnalysisRun).where(AnalysisRun.scan_id == scan_id)).one()
        result = analyze(analysis_service.build_observations(repo, scan))
        analysis_service.record_rule_versions(repo)
        analysis_service.persist_result(repo, scan, run, result)
        s.commit()
    assert (scan_env.count("findings", scan_id), _links(scan_env, scan_id)) == before


def _links(env: ScanEnv, scan_id: uuid.UUID) -> int:
    with env.factory() as s:
        return int(
            s.scalar(
                text("SELECT count(*) FROM finding_evidence WHERE scan_id = :s"), {"s": scan_id}
            )
        )


def test_an_error_while_analysing_fails_the_run_without_partial_writes(
    scan_env: ScanEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    golden_site(scan_env.site)
    _, _, scan_id = scan_env.queued_scan()
    worker = scan_env.worker()
    assert worker.run_once()

    original = analysis_service.persist_result

    def persist_then_fail(*args: Any) -> int:
        original(*args)  # writes findings, then fails: all must be rolled back
        raise RuntimeError(f"target said {SESSION_SECRET}")

    monkeypatch.setattr(analysis_service, "persist_result", persist_then_fail)
    assert worker.run_once()
    run = run_of(scan_env, scan_id)
    assert run.status is AnalysisStatus.FAILED
    assert run.error_code == "analysis_error"
    assert run.finished_at is not None
    assert scan_env.count("findings", scan_id) == 0
    assert SESSION_SECRET not in scan_env.all_text(scan_id)
    assert not worker.run_once()  # failed runs are not retried


def test_a_crash_leaves_the_run_queued_for_the_next_worker(
    scan_env: ScanEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    golden_site(scan_env.site)
    _, _, scan_id = scan_env.queued_scan()
    assert scan_env.worker().run_once()

    class Crash(BaseException):
        """Stands in for the process dying mid-analysis."""

    def crash(*_: Any) -> None:
        raise Crash

    with monkeypatch.context() as m:
        m.setattr(worker_core, "execute_run", crash)
        with pytest.raises(Crash):
            scan_env.worker("worker-crashing").analyze_once()
    assert run_of(scan_env, scan_id).status is AnalysisStatus.QUEUED
    assert scan_env.count("findings", scan_id) == 0

    assert scan_env.worker("worker-b").analyze_once()
    assert run_of(scan_env, scan_id).status is AnalysisStatus.COMPLETED
    assert scan_env.count("findings", scan_id) > 0


def test_a_failing_rule_is_isolated_and_recorded_by_type_only(
    scan_env: ScanEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sentinel_analysis import REGISTRY

    golden_site(scan_env.site)
    _, _, scan_id = scan_env.queued_scan()
    assert scan_env.worker().run_once()

    def explode(_: object) -> list[Any]:
        raise ValueError(f"leaky {SESSION_SECRET}")

    broken = Rule(REGISTRY[0].meta, explode)  # same id: replaces SV-CKE-001 for this run
    rules = (broken, *REGISTRY[1:])
    monkeypatch.setattr(analysis_service, "analyze", lambda obs: analyze(obs, rules))
    assert scan_env.worker().run_once()

    run = run_of(scan_env, scan_id)
    assert run.status is AnalysisStatus.COMPLETED
    assert run.rule_errors == [{"rule_id": REGISTRY[0].meta.id, "error": "ValueError"}]
    rule_ids = {f.rule_id for f in findings_of(scan_env, scan_id)}
    assert REGISTRY[0].meta.id not in rule_ids
    assert "SV-TRN-001" in rule_ids  # the other rules still ran
    assert SESSION_SECRET not in scan_env.all_text(scan_id)


def test_changed_rule_metadata_without_a_version_bump_fails_the_run(
    scan_env: ScanEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dataclasses import replace

    from sentinel_analysis import REGISTRY

    # A rule id that exists only in this test, so the immutable global table
    # holds nothing a real rule could collide with.
    test_rule = Rule(replace(REGISTRY[0].meta, id="SV-TST-901", title="Original"), lambda _: [])
    monkeypatch.setattr(analysis_service, "REGISTRY", (test_rule,))
    with scan_env.factory() as s:
        analysis_service.record_rule_versions(AnalysisRepository(s))
        s.commit()

    changed = Rule(replace(test_rule.meta, title="Changed"), lambda _: [])
    monkeypatch.setattr(analysis_service, "REGISTRY", (changed,))
    _, _, scan_id = scan_env.queued_scan()
    assert scan_env.worker().run_once()
    assert scan_env.worker().run_once()
    run = run_of(scan_env, scan_id)
    assert run.status is AnalysisStatus.FAILED
    assert run.error_code == "rule_metadata_conflict"


def test_runs_queued_for_another_ruleset_are_failed_not_misattributed(
    scan_env: ScanEnv,
) -> None:
    _, _, scan_id = scan_env.queued_scan()
    worker = scan_env.worker()
    assert worker.run_once()
    with scan_env.factory() as s:
        s.execute(
            text(
                "UPDATE analysis_runs SET ruleset_version = 'rs-0000000000000000' "
                "WHERE scan_id = :s"
            ),
            {"s": scan_id},
        )
        s.commit()
    assert worker.run_once()
    run = run_of(scan_env, scan_id)
    assert run.status is AnalysisStatus.FAILED
    assert run.error_code == "ruleset_version_mismatch"


# --- concurrency -----------------------------------------------------------------------


def test_a_locked_run_is_skipped_by_other_workers(scan_env: ScanEnv) -> None:
    _, _, scan_id = scan_env.queued_scan()
    assert scan_env.worker().run_once()
    run_id = run_of(scan_env, scan_id).id
    with scan_env.factory() as holder:
        AnalysisRepository(holder).get_run_for_update(run_id, skip_locked=False)
        assert not scan_env.worker("worker-b").analyze_once()
        holder.rollback()
    assert scan_env.worker("worker-b").analyze_once()


@pytest.mark.parametrize("attempt", range(3))
def test_concurrent_workers_analyse_each_run_exactly_once(scan_env: ScanEnv, attempt: int) -> None:
    golden_site(scan_env.site)
    scan_ids = [scan_env.queued_scan()[2] for _ in range(2)]
    scanner = scan_env.worker()
    for _ in scan_ids:  # scans only (run_once would also pick up analysis work)
        claimed = scanner.claim()
        assert claimed is not None
        scanner.execute(claimed)
    barrier = threading.Barrier(4)
    processed: list[bool] = []
    lock = threading.Lock()

    def work(name: str) -> None:
        worker = scan_env.worker(name)
        barrier.wait()
        done = worker.analyze_once()
        with lock:
            processed.append(done)

    threads = [threading.Thread(target=work, args=(f"w{attempt}-{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    with scan_env.factory() as s:
        statuses = s.scalars(
            select(AnalysisRun.status).where(AnalysisRun.scan_id.in_(scan_ids))
        ).all()
    remaining = statuses.count(AnalysisStatus.QUEUED)
    # Every processed run completed exactly once; anything a worker skipped
    # because it was locked is still queued and is picked up afterwards.
    assert processed.count(True) == statuses.count(AnalysisStatus.COMPLETED)
    while remaining:
        assert scan_env.worker().analyze_once()
        remaining -= 1
    for scan_id in scan_ids:
        assert run_of(scan_env, scan_id).status is AnalysisStatus.COMPLETED
    a, b = ({f.fingerprint for f in findings_of(scan_env, sid)} for sid in scan_ids)
    assert a == b and len(a) == scan_env.count("findings", scan_ids[0])


# --- TLS certificate-verification contract (local self-signed server) -----------------


@pytest.fixture
def tls_env(scan_env: ScanEnv) -> Iterator[ScanEnv]:
    with LabSite(tls=self_signed_server_context()) as site:
        site.html("/", "<title>TLS lab</title>")
        yield ScanEnv(scan_env.factory, site, scan_env.project_id)


def test_untrusted_certificate_produces_the_documented_event_and_trn_002(
    tls_env: ScanEnv,
) -> None:
    scan_id = scan_and_analyse(tls_env)
    with tls_env.factory() as s:
        events = s.execute(
            text("SELECT code, message FROM scan_logs WHERE scan_id = :s AND code = 'tls_error'"),
            {"s": scan_id},
        ).all()
    assert events, "the scanner must report the certificate failure as a tls_error event"
    assert all("CERTIFICATE_VERIFY_FAILED" in message for _, message in events)

    findings = findings_of(tls_env, scan_id)
    assert [(f.rule_id, f.subject_key) for f in findings] == [
        ("SV-TRN-002", f"https://lab.test:{tls_env.site.port}")
    ]
    assert findings[0].details["reason"] == "CERTIFICATE_VERIFY_FAILED"


def test_allow_untrusted_tls_records_coverage_instead_of_a_finding(tls_env: ScanEnv) -> None:
    scan_id = scan_and_analyse(tls_env, allow_untrusted_tls=True)
    rule_ids = {f.rule_id for f in findings_of(tls_env, scan_id)}
    assert "SV-TRN-002" not in rule_ids
    assert "SV-HDR-001" in rule_ids  # the page was fetched over HTTPS without HSTS
    assert "tls_trust_not_evaluated" in run_of(tls_env, scan_id).coverage_notes


# --- API ------------------------------------------------------------------------------


def test_findings_api_end_to_end(scan_env: ScanEnv, committed_api: TestClient) -> None:
    golden_site(scan_env.site)
    scan_id = scan_and_analyse(scan_env)
    api = committed_api

    listed = api.get(f"/api/v1/scans/{scan_id}/findings", params={"limit": 100})
    assert listed.status_code == 200
    rows = listed.json()
    assert len(rows) == 12
    assert all(r["title"] for r in rows)

    lows = api.get(f"/api/v1/scans/{scan_id}/findings", params={"severity": "low"}).json()
    assert lows and all(r["severity"] == "low" for r in lows)
    cke = api.get(f"/api/v1/scans/{scan_id}/findings", params={"rule_id": "SV-CKE-001"}).json()
    assert [r["rule_id"] for r in cke] == ["SV-CKE-001"]
    assert (
        api.get(f"/api/v1/scans/{scan_id}/findings", params={"severity": "bad"}).status_code == 422
    )
    assert (
        api.get(f"/api/v1/scans/{scan_id}/findings", params={"rule_id": "x' OR 1=1"}).status_code
        == 422
    )

    summary = api.get(f"/api/v1/scans/{scan_id}/findings/summary").json()
    assert summary["total"] == 12
    assert summary["by_status"] == {"open": 12}
    assessment_id = scan_env.get_scan(scan_id).assessment_id
    assert api.get(f"/api/v1/assessments/{assessment_id}/findings/summary").json()["total"] == 12

    runs = api.get(f"/api/v1/scans/{scan_id}/analysis").json()
    assert [r["status"] for r in runs] == ["completed"]

    rules = api.get("/api/v1/rules").json()
    assert rules["ruleset_version"] == RULESET_VERSION
    assert len(rules["rules"]) == 14

    finding = cke[0]
    detail = api.get(f"/api/v1/findings/{finding['id']}").json()
    assert detail["rule"]["id"] == "SV-CKE-001"
    assert detail["rule"]["proves"] and detail["rule"]["does_not_prove"]
    evidence = api.get(f"/api/v1/findings/{finding['id']}/evidence").json()
    assert {e["id"] for e in evidence} == set(detail["evidence_ids"])
    assert SESSION_SECRET not in str(evidence)

    for missing in ("/findings/{id}", "/findings/{id}/evidence", "/findings/{id}/history"):
        assert api.get("/api/v1" + missing.format(id=uuid.uuid4())).status_code == 404
    assert api.get(f"/api/v1/scans/{uuid.uuid4()}/findings").status_code == 404
    assert api.get(f"/api/v1/assessments/{uuid.uuid4()}/findings/summary").status_code == 404


def test_triage_requires_reasons_and_records_history(
    scan_env: ScanEnv, committed_api: TestClient
) -> None:
    golden_site(scan_env.site)
    scan_id = scan_and_analyse(scan_env)
    api = committed_api
    finding_id = api.get(f"/api/v1/scans/{scan_id}/findings").json()[0]["id"]
    url = f"/api/v1/findings/{finding_id}/triage"

    no_reason = api.post(url, json={"status": "false_positive", "triaged_by": "Tester"})
    assert no_reason.status_code == 422
    blank = api.post(url, json={"status": "accepted_risk", "reason": "  ", "triaged_by": "T"})
    assert blank.status_code == 422
    assert api.post(url, json={"status": "fixed", "triaged_by": "T"}).status_code == 422
    assert api.post(url, json={"status": "open", "triaged_by": "T"}).status_code == 409
    assert (
        api.post(url, json={"status": "confirmed", "triaged_by": "T", "extra": 1}).status_code
        == 422
    )

    confirmed = api.post(url, json={"status": "confirmed", "triaged_by": "Tester"})
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "confirmed"
    fp = api.post(
        url, json={"status": "false_positive", "reason": "lab artefact", "triaged_by": "Lead"}
    )
    assert fp.status_code == 200
    assert fp.json()["status_reason"] == "lab artefact"

    # Since Phase 9 M4 the recorded actor is the authenticated user; the
    # body's triaged_by is accepted but not trusted (M5 removes it).
    actor = api.get("/api/v1/auth/me").json()["user"]["username"]
    history = api.get(f"/api/v1/findings/{finding_id}/history").json()
    assert [(h["from_status"], h["to_status"], h["changed_by"]) for h in history] == [
        ("open", "confirmed", actor),
        ("confirmed", "false_positive", actor),
    ]
    assert fp.json()["status_changed_by"] == actor


def test_concurrent_triage_serializes_on_the_finding(
    scan_env: ScanEnv, committed_api: TestClient
) -> None:
    golden_site(scan_env.site)
    scan_id = scan_and_analyse(scan_env)
    finding_id = committed_api.get(f"/api/v1/scans/{scan_id}/findings").json()[0]["id"]
    url = f"/api/v1/findings/{finding_id}/triage"
    barrier = threading.Barrier(2)
    codes: list[int] = []

    def triage() -> None:
        barrier.wait()
        codes.append(
            committed_api.post(url, json={"status": "confirmed", "triaged_by": "T"}).status_code
        )

    threads = [threading.Thread(target=triage) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert sorted(codes) == [200, 409]  # the second sees the first's committed change
    history = committed_api.get(f"/api/v1/findings/{finding_id}/history").json()
    assert len(history) == 1
