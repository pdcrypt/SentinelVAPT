"""Phase 6 retests and comparisons end to end against a 127.0.0.1 lab site:
the A -> B -> C golden chain, refusals, idempotency, concurrency, worker
crashes, triage locking, database guarantees and Phase 5 report history."""

import threading
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sentinel_analysis import REGISTRY, analyze
from sentinel_analysis.rules.base import Rule
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError

from app.api.deps import (
    get_assessment_service,
    get_comparison_service,
    get_finding_service,
    get_retest_service,
    get_target_service,
)
from app.core.clock import utc_now
from app.core.errors import ComparisonNotAllowedError, NotFoundError, RetestNotAllowedError
from app.models import (
    Comparison,
    ComparisonRecord,
    Finding,
    Report,
    ReportArtifact,
)
from app.models.enums import ComparisonStatus, FindingStatus, ReportStatus
from app.repositories import AnalysisRepository, ComparisonRepository
from app.schemas.report import ReportCreate
from app.schemas.retest import RetestCreate
from app.schemas.target import TargetUpdate
from app.services import analysis as analysis_service
from app.services import comparisons as comparison_service
from app.worker import WorkerRole
from sentinel_reports import render_report
from tests.integration.lab_site import LabSite
from tests.integration.scan_support import ScanEnv, authorization
from tests.integration.test_analysis import committed_api

pytestmark = pytest.mark.integration

__all__ = ["committed_api"]  # fixture re-exported for this module

CSP = "default-src 'self'; frame-ancestors 'none'"


# --- lab site versions -----------------------------------------------------------------------


def site_a(site: LabSite) -> None:
    site.pages.clear()
    site.html(
        "/",
        '<title>Home</title><a href="/about">About</a><a href="/error">Error</a>'
        '<a href="/version">Version</a>',
        headers=[
            ("X-Powered-By", "PHP/8.1.0"),
            ("Set-Cookie", "SESSIONID=LAB-SECRET; Path=/"),
            ("Allow", "GET, HEAD, OPTIONS, PUT"),
        ],
    )
    site.html("/about", "<title>About</title>", headers=[("Access-Control-Allow-Origin", "*")])
    site.html(
        "/error",
        "<title>Error</title><pre>Traceback (most recent call last):\n  File x</pre>",
        status=500,
    )


def site_b(site: LabSite) -> None:
    """CSP and framing fixed everywhere, X-Powered-By removed, wildcard CORS
    removed, a new page disclosing X-AspNet-Version, one more risky method.
    (The lab server's own Server header always carries a version.)"""
    site_a(site)
    site.html(
        "/",
        '<title>Home</title><a href="/about">About</a><a href="/error">Error</a>'
        '<a href="/version">Version</a>',
        headers=[
            ("Set-Cookie", "SESSIONID=LAB-SECRET; Path=/"),
            ("Allow", "GET, HEAD, OPTIONS, PUT, DELETE"),
            ("Content-Security-Policy", CSP),
        ],
    )
    site.html("/about", "<title>About</title>", headers=[("Content-Security-Policy", CSP)])
    site.html(
        "/version",
        "<title>Version</title>",
        headers=[("X-AspNet-Version", "4.0.30319"), ("Content-Security-Policy", CSP)],
    )


def site_c(site: LabSite) -> None:
    """The home page loses its CSP again (regression)."""
    site_b(site)
    site.html(
        "/",
        '<title>Home</title><a href="/about">About</a><a href="/error">Error</a>'
        '<a href="/version">Version</a>',
        headers=[
            ("Set-Cookie", "SESSIONID=LAB-SECRET; Path=/"),
            ("Allow", "GET, HEAD, OPTIONS, PUT, DELETE"),
        ],
    )


# --- helpers ---------------------------------------------------------------------------------


def run_scan(env: ScanEnv, assessment_id: uuid.UUID) -> uuid.UUID:
    """Scan and analyse an in-progress assessment; returns the scan id."""
    scan_id = env.scan(assessment_id)
    worker = env.worker(role=WorkerRole.SCANS)
    claimed = worker.claim()
    assert claimed is not None and claimed.scan_id == scan_id
    worker.execute(claimed)
    assert worker.analyze_once()
    return scan_id


def start(env: ScanEnv, assessment_id: uuid.UUID) -> None:
    with env.factory() as s:
        get_assessment_service(s, utc_now).start(assessment_id, actor=env.actor)


def complete(env: ScanEnv, assessment_id: uuid.UUID) -> None:
    with env.factory() as s:
        get_assessment_service(s, utc_now).complete(assessment_id, actor=env.actor)


def create_retest(env: ScanEnv, parent_id: uuid.UUID, **kw: Any) -> uuid.UUID:
    with env.factory() as s:
        data = RetestCreate.model_validate({"name": "Retest", **kw})
        return get_retest_service(s, utc_now).create(parent_id, data, actor=env.actor).id


def request_comparison(env: ScanEnv, assessment_id: uuid.UUID, scan_id: uuid.UUID) -> Any:
    with env.factory() as s:
        comparison, created = get_comparison_service(s).request(
            assessment_id, scan_id, actor=env.actor
        )
        s.expunge(comparison)
        return comparison, created


def records_of(env: ScanEnv, comparison_id: uuid.UUID) -> dict[tuple[str, str, str], Any]:
    """(rule, subject, discriminator) -> (state, reasons)"""
    with env.factory() as s:
        rows = s.scalars(
            select(ComparisonRecord).where(ComparisonRecord.comparison_id == comparison_id)
        ).all()
        result = {}
        for r in rows:
            finding = s.get(Finding, r.current_finding_id or r.baseline_finding_id)
            assert finding is not None
            result[(r.rule_id, finding.subject_key.replace(env.site.url("/")[:-1], ""),
                    finding.discriminator)] = (str(r.state), tuple(r.reasons))  # fmt: skip
        return result


def load_comparison(env: ScanEnv, comparison_id: uuid.UUID) -> Comparison:
    with env.factory() as s:
        comparison = s.get(Comparison, comparison_id)
        assert comparison is not None
        s.expunge(comparison)
        return comparison


def mark_false_positive(env: ScanEnv, scan_id: uuid.UUID, rule_id: str) -> None:
    with env.factory() as s:
        finding = s.scalars(
            select(Finding).where(Finding.scan_id == scan_id, Finding.rule_id == rule_id)
        ).one()
        get_finding_service(s, utc_now).triage(
            finding.id, FindingStatus.FALSE_POSITIVE, "lab artefact", actor=env.actor
        )


def narrow_scope(env: ScanEnv, target_id: uuid.UUID, excluded: list[str]) -> None:
    with env.factory() as s:
        get_target_service(s, utc_now).update(
            target_id,
            TargetUpdate.model_validate(
                {"excluded_paths": excluded, "authorization": authorization(reference="LAB-NARROW")}
            ),
            actor=env.actor,
        )


def broken_rule(rule_id: str) -> tuple[Rule, ...]:
    def explode(_: object) -> list[Any]:
        raise RuntimeError("forced rule error")

    return tuple(Rule(r.meta, explode) if r.meta.id == rule_id else r for r in REGISTRY)


@pytest.fixture
def baseline(scan_env: ScanEnv) -> dict[str, uuid.UUID]:
    """Assessment A, scanned against site version A, completed."""
    site_a(scan_env.site)
    target_id = scan_env.target()
    a = scan_env.started_assessment(target_id)
    scan_a = run_scan(scan_env, a)
    complete(scan_env, a)
    return {"target": target_id, "a": a, "scan_a": scan_a}


# --- golden chain A -> B -> C ------------------------------------------------------------------


def test_golden_retest_chain(
    scan_env: ScanEnv, baseline: dict[str, uuid.UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    env, a, scan_a = scan_env, baseline["a"], baseline["scan_a"]

    # A Phase 5 report of A, generated before any retest.
    with env.factory() as s:
        from app.api.deps import get_report_service

        report_id = get_report_service(s, utc_now).create(
            a,
            ReportCreate.model_validate(
                {"scan_id": str(scan_a), "kind": "final", "title": "A", "formats": ["json", "html"]}
            ),
            actor=env.actor,
        ).id  # fmt: skip
    assert env.worker(role=WorkerRole.REPORTS).run_once()
    with env.factory() as s:
        report_before = s.get(Report, report_id)
        assert report_before is not None and report_before.status is ReportStatus.COMPLETED
        snapshot_before = dict(report_before.snapshot)
        artifacts_before = {
            x.format: x.content
            for x in s.scalars(select(ReportArtifact).where(ReportArtifact.report_id == report_id))
        }

    mark_false_positive(env, scan_a, "SV-COR-001")

    # --- B: retest of A -------------------------------------------------------------------
    b = create_retest(env, a, name="Retest B")
    start(env, b)
    site_b(env.site)
    scan_b = run_scan(env, b)
    complete(env, b)
    comparison_b, created = request_comparison(env, b, scan_b)
    assert created and comparison_b.status is ComparisonStatus.QUEUED
    assert env.worker(role=WorkerRole.SCANS).run_once()  # computes the comparison
    cmp_b = load_comparison(env, comparison_b.id)
    assert cmp_b.status is ComparisonStatus.COMPLETED, cmp_b.error_code
    assert cmp_b.baseline_scan_id == scan_a and cmp_b.previous_comparison_id is None

    assert records_of(env, cmp_b.id) == {
        ("SV-TRN-001", "", ""): ("unchanged", ()),
        ("SV-HDR-002", "", ""): ("fixed", ("examined_condition_absent",)),
        ("SV-HDR-003", "", ""): ("fixed", ("examined_condition_absent",)),
        ("SV-HDR-004", "", ""): ("unchanged", ()),
        ("SV-CKE-001", "", "SESSIONID"): ("unchanged", ()),
        ("SV-CKE-003", "", "SESSIONID"): ("unchanged", ()),
        ("SV-INF-001", "", "server"): ("unchanged", ()),
        ("SV-INF-001", "", "x-powered-by"): ("fixed", ("examined_condition_absent",)),
        ("SV-INF-001", "", "x-aspnet-version"): ("new", ("first_observed",)),
        ("SV-INF-002", "GET /error", ""): ("unchanged", ()),
        ("SV-COR-001", "", ""): (
            "dismissed",
            ("baseline_false_positive", "examined_condition_absent"),
        ),
        ("SV-MTH-001", "OPTIONS /", ""): ("still_open", ("details_changed",)),
    }
    assert cmp_b.summary is not None
    assert cmp_b.summary["states"]["fixed"] == 3 and cmp_b.summary["policy_version"] == "cmp-1"

    # Coverage evidence: only for fixed/dismissed records, only from scan B.
    with env.factory() as s:
        rows = s.execute(
            text(
                "SELECT r.state, e.scan_id FROM comparison_coverage_evidence c "
                "JOIN comparison_records r ON r.comparison_id = c.comparison_id "
                "AND r.fingerprint = c.fingerprint JOIN evidence e ON e.id = c.evidence_id "
                "WHERE c.comparison_id = :c"
            ),
            {"c": cmp_b.id},
        ).all()
    assert rows and {state for state, _ in rows} == {"fixed", "dismissed"}
    assert {scan for _, scan in rows} == {scan_b}

    # --- C: retest of B, narrower scope, CKE-001 fails during analysis ----------------------
    narrow_scope(env, baseline["target"], ["/admin", "/error"])
    c = create_retest(env, b, name="Retest C")
    start(env, c)
    site_c(env.site)
    with monkeypatch.context() as m:
        m.setattr(analysis_service, "analyze", lambda obs: analyze(obs, broken_rule("SV-CKE-001")))
        scan_c = run_scan(env, c)
    complete(env, c)
    comparison_c, _ = request_comparison(env, c, scan_c)
    assert env.worker(role=WorkerRole.SCANS).run_once()
    cmp_c = load_comparison(env, comparison_c.id)
    assert cmp_c.status is ComparisonStatus.COMPLETED, cmp_c.error_code
    assert cmp_c.previous_comparison_id == cmp_b.id and cmp_c.baseline_scan_id == scan_b

    assert records_of(env, cmp_c.id) == {
        ("SV-TRN-001", "", ""): ("unchanged", ()),
        ("SV-HDR-002", "", ""): ("reopened", ("previously_fixed",)),
        ("SV-HDR-003", "", ""): ("reopened", ("previously_fixed",)),
        ("SV-HDR-004", "", ""): ("unchanged", ()),
        ("SV-CKE-001", "", "SESSIONID"): ("not_comparable", ("rule_error",)),
        ("SV-CKE-003", "", "SESSIONID"): ("unchanged", ()),
        ("SV-INF-001", "", "server"): ("unchanged", ()),
        ("SV-INF-001", "", "x-aspnet-version"): ("unchanged", ()),
        ("SV-INF-002", "GET /error", ""): ("not_retested", ("out_of_scope",)),
        ("SV-MTH-001", "OPTIONS /", ""): ("unchanged", ()),
    }

    # Lineage A -> B -> C.
    with env.factory() as s:
        lineage = get_retest_service(s, utc_now).lineage(c)
    assert [e["assessment_id"] for e in lineage] == [a, b, c]
    assert [len(e["comparisons"]) for e in lineage] == [0, 1, 1]

    # Comparing again is idempotent and recomputation gives identical records.
    again, created = request_comparison(env, c, scan_c)
    assert not created and again.id == cmp_c.id
    recomputed = recompute(env, cmp_c.id)
    assert recomputed == stored_records(env, cmp_c.id)

    # History is untouched: findings' triage, Phase 5 report and artifacts.
    with env.factory() as s:
        report_after = s.get(Report, report_id)
        assert report_after is not None
        assert report_after.snapshot == snapshot_before
        artifacts_after = {
            x.format: x.content
            for x in s.scalars(select(ReportArtifact).where(ReportArtifact.report_id == report_id))
        }
        fp_finding = s.scalars(
            select(Finding).where(Finding.scan_id == scan_a, Finding.rule_id == "SV-COR-001")
        ).one()
        assert fp_finding.status is FindingStatus.FALSE_POSITIVE
    assert artifacts_after == artifacts_before  # byte-identical
    rerendered = {x.format: x.content for x in render_report(snapshot_before, ["json", "html"])}
    assert rerendered == artifacts_before


def stored_records(env: ScanEnv, comparison_id: uuid.UUID) -> list[tuple[Any, ...]]:
    with env.factory() as s:
        return [
            (r.fingerprint, str(r.state), tuple(r.reasons))
            for r in s.scalars(
                select(ComparisonRecord)
                .where(ComparisonRecord.comparison_id == comparison_id)
                .order_by(ComparisonRecord.fingerprint)
            )
        ]


def recompute(env: ScanEnv, comparison_id: uuid.UUID) -> list[tuple[Any, ...]]:
    """Recompute a comparison's classification from the same persisted data,
    in a transaction that is rolled back."""
    with env.factory() as s:
        comparison = s.get(Comparison, comparison_id)
        assert comparison is not None
        records = comparison_service.compute_records(s, comparison)
        s.rollback()
    return [(r.fingerprint, r.state.value, r.reasons) for r in records]


# --- retest creation rules -------------------------------------------------------------------


def test_retest_requires_a_completed_parent(scan_env: ScanEnv) -> None:
    site_a(scan_env.site)
    a = scan_env.started_assessment(scan_env.target())
    with pytest.raises(RetestNotAllowedError) as info:
        create_retest(scan_env, a)
    assert info.value.reason == "parent_not_completed"


def test_retest_requires_an_analysed_baseline(scan_env: ScanEnv) -> None:
    site_a(scan_env.site)
    a = scan_env.started_assessment(scan_env.target())
    scan_id = scan_env.scan(a)
    worker = scan_env.worker(role=WorkerRole.SCANS)
    claimed = worker.claim()
    assert claimed is not None
    worker.execute(claimed)  # completed, analysis still queued
    complete(scan_env, a)
    with pytest.raises(RetestNotAllowedError) as info:
        create_retest(scan_env, a)
    assert info.value.reason == "baseline_not_analysed"
    with pytest.raises(RetestNotAllowedError):
        create_retest(scan_env, a, baseline_scan_id=str(scan_id))


def test_baseline_scan_must_belong_to_the_parent(
    scan_env: ScanEnv, baseline: dict[str, uuid.UUID]
) -> None:
    other_target = scan_env.target()
    other = scan_env.started_assessment(other_target)
    other_scan = run_scan(scan_env, other)
    with pytest.raises(NotFoundError):
        create_retest(scan_env, baseline["a"], baseline_scan_id=str(other_scan))


def test_scope_expansion_is_refused(scan_env: ScanEnv, baseline: dict[str, uuid.UUID]) -> None:
    with scan_env.factory() as s:
        get_target_service(s, utc_now).update(
            baseline["target"],
            TargetUpdate.model_validate(
                {
                    "in_scope_hosts": ["lab.test", "lab2.test"],
                    "authorization": authorization(reference="LAB-WIDER"),
                }
            ),
            actor=scan_env.actor,
        )
    with pytest.raises(RetestNotAllowedError) as info:
        create_retest(scan_env, baseline["a"])
    assert info.value.reason == "scope_expanded"
    # Dropping an exclusion the parent had is also an expansion.
    with scan_env.factory() as s:
        get_target_service(s, utc_now).update(
            baseline["target"],
            TargetUpdate.model_validate(
                {
                    "in_scope_hosts": ["lab.test"],
                    "excluded_paths": [],
                    "authorization": authorization(reference="LAB-NOEXCL"),
                }
            ),
            actor=scan_env.actor,
        )
    with pytest.raises(RetestNotAllowedError) as info:
        create_retest(scan_env, baseline["a"])
    assert info.value.reason == "scope_expanded"


def test_expired_authorization_is_refused(
    scan_env: ScanEnv, baseline: dict[str, uuid.UUID]
) -> None:
    later = datetime.now(UTC) + timedelta(days=30)
    with scan_env.factory() as s:
        service = get_retest_service(s, lambda: later)
        with pytest.raises(RetestNotAllowedError) as info:
            service.create(baseline["a"], RetestCreate(name="Late"), actor=scan_env.actor)
    assert info.value.reason == "authorization_expired"


def test_one_live_retest_per_assessment(scan_env: ScanEnv, baseline: dict[str, uuid.UUID]) -> None:
    first = create_retest(scan_env, baseline["a"])
    with pytest.raises(RetestNotAllowedError) as info:
        create_retest(scan_env, baseline["a"])
    assert info.value.reason == "retest_exists"
    with scan_env.factory() as s:
        get_assessment_service(s, utc_now).cancel(first, actor=scan_env.actor)
    assert create_retest(scan_env, baseline["a"]) != first  # a cancelled retest frees the slot


@pytest.mark.parametrize("attempt", range(3))
def test_concurrent_retest_creation_yields_one(
    scan_env: ScanEnv, baseline: dict[str, uuid.UUID], attempt: int
) -> None:
    barrier = threading.Barrier(4)
    outcomes: list[str] = []
    lock = threading.Lock()

    def create() -> None:
        barrier.wait()
        try:
            create_retest(scan_env, baseline["a"], name=f"R{attempt}")
            result = "created"
        except RetestNotAllowedError as exc:
            result = exc.reason
        except IntegrityError:
            result = "integrity"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=create) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert outcomes.count("created") == 1
    assert set(outcomes) <= {"created", "retest_exists", "integrity"}


# --- comparison requests ---------------------------------------------------------------------


def test_comparison_request_rules(scan_env: ScanEnv, baseline: dict[str, uuid.UUID]) -> None:
    a, scan_a = baseline["a"], baseline["scan_a"]
    with pytest.raises(ComparisonNotAllowedError) as info:
        request_comparison(scan_env, a, scan_a)
    assert info.value.reason == "not_a_retest"

    b = create_retest(scan_env, a)
    start(scan_env, b)
    with pytest.raises(NotFoundError):
        request_comparison(scan_env, b, scan_a)  # a scan of another assessment
    scan_b = scan_env.scan(b)
    with pytest.raises(ComparisonNotAllowedError) as info:
        request_comparison(scan_env, b, scan_b)
    assert info.value.reason == "scan_not_completed"
    worker = scan_env.worker(role=WorkerRole.SCANS)
    claimed = worker.claim()
    assert claimed is not None
    worker.execute(claimed)
    with pytest.raises(ComparisonNotAllowedError) as info:
        request_comparison(scan_env, b, scan_b)
    assert info.value.reason == "analysis_not_completed"
    assert worker.analyze_once()
    complete(scan_env, b)

    # C (retest of B) cannot be compared before B's comparison exists.
    c = create_retest(scan_env, b)
    start(scan_env, c)
    scan_c = run_scan(scan_env, c)
    with pytest.raises(ComparisonNotAllowedError) as info:
        request_comparison(scan_env, c, scan_c)
    assert info.value.reason == "previous_comparison_missing"
    request_comparison(scan_env, b, scan_b)
    with pytest.raises(ComparisonNotAllowedError) as info:
        request_comparison(scan_env, c, scan_c)
    assert info.value.reason == "previous_comparison_not_completed"


def test_expired_authorization_does_not_block_offline_comparison(
    scan_env: ScanEnv, baseline: dict[str, uuid.UUID]
) -> None:
    b = create_retest(scan_env, baseline["a"])
    start(scan_env, b)
    scan_b = run_scan(scan_env, b)
    complete(scan_env, b)
    with scan_env.factory() as s:  # the authorization window has since closed
        s.execute(
            text(
                "ALTER TABLE target_authorizations DISABLE TRIGGER target_authorizations_immutable"
            )
        )
        s.execute(
            text(
                "UPDATE target_authorizations SET valid_from = now() - interval '2 days', "
                "valid_until = now() - interval '1 day' WHERE target_id = :t"
            ),
            {"t": baseline["target"]},
        )
        s.execute(
            text("ALTER TABLE target_authorizations ENABLE TRIGGER target_authorizations_immutable")
        )
        s.commit()
    comparison, created = request_comparison(scan_env, b, scan_b)
    assert created
    assert scan_env.worker(role=WorkerRole.SCANS).compare_once()
    assert load_comparison(scan_env, comparison.id).status is ComparisonStatus.COMPLETED


@pytest.fixture
def retest_b(scan_env: ScanEnv, baseline: dict[str, uuid.UUID]) -> dict[str, uuid.UUID]:
    b = create_retest(scan_env, baseline["a"])
    start(scan_env, b)
    site_b(scan_env.site)
    scan_b = run_scan(scan_env, b)
    complete(scan_env, b)
    return {**baseline, "b": b, "scan_b": scan_b}


@pytest.mark.parametrize("attempt", range(3))
def test_duplicate_and_concurrent_requests_create_one_comparison(
    scan_env: ScanEnv, retest_b: dict[str, uuid.UUID], attempt: int
) -> None:
    barrier = threading.Barrier(4)
    created: list[bool] = []
    lock = threading.Lock()

    def request() -> None:
        barrier.wait()
        _, new = request_comparison(scan_env, retest_b["b"], retest_b["scan_b"])
        with lock:
            created.append(new)

    threads = [threading.Thread(target=request) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert created.count(True) == 1
    with scan_env.factory() as s:
        count = s.scalar(
            text("SELECT count(*) FROM comparisons WHERE current_scan_id = :s"),
            {"s": retest_b["scan_b"]},
        )
    assert count == 1


@pytest.mark.parametrize("attempt", range(3))
def test_concurrent_workers_compute_each_comparison_once(
    scan_env: ScanEnv, retest_b: dict[str, uuid.UUID], attempt: int
) -> None:
    comparison, _ = request_comparison(scan_env, retest_b["b"], retest_b["scan_b"])
    barrier = threading.Barrier(4)
    done: list[bool] = []
    lock = threading.Lock()

    def work(name: str) -> None:
        worker = scan_env.worker(name, role=WorkerRole.SCANS)
        barrier.wait()
        result = worker.compare_once()
        with lock:
            done.append(result)

    threads = [threading.Thread(target=work, args=(f"c{attempt}-{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert done.count(True) == 1
    assert load_comparison(scan_env, comparison.id).status is ComparisonStatus.COMPLETED


def test_a_crash_leaves_the_comparison_queued(
    scan_env: ScanEnv, retest_b: dict[str, uuid.UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    comparison, _ = request_comparison(scan_env, retest_b["b"], retest_b["scan_b"])

    class Crash(BaseException):
        """Stands in for the process dying mid-comparison."""

    def crash(*_: Any) -> None:
        raise Crash

    from app.worker import core as worker_core

    with monkeypatch.context() as m:
        m.setattr(worker_core, "execute_comparison", crash)
        with pytest.raises(Crash):
            scan_env.worker("crashing", role=WorkerRole.SCANS).compare_once()
    assert load_comparison(scan_env, comparison.id).status is ComparisonStatus.QUEUED
    with scan_env.factory() as s:
        assert not s.scalar(
            text("SELECT count(*) FROM comparison_records WHERE comparison_id = :c"),
            {"c": comparison.id},
        )
    assert scan_env.worker("next", role=WorkerRole.SCANS).compare_once()
    assert load_comparison(scan_env, comparison.id).status is ComparisonStatus.COMPLETED


def test_a_handled_error_fails_the_comparison_with_a_code_only(
    scan_env: ScanEnv, retest_b: dict[str, uuid.UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    comparison, _ = request_comparison(scan_env, retest_b["b"], retest_b["scan_b"])
    real = getattr(comparison_service, "classify")  # noqa: B009  # re-exported name

    def classify_then_fail(*args: Any) -> Any:
        real(*args)
        raise RuntimeError("secret LAB-SECRET")

    monkeypatch.setattr(comparison_service, "classify", classify_then_fail)
    assert scan_env.worker(role=WorkerRole.SCANS).compare_once()
    failed = load_comparison(scan_env, comparison.id)
    assert failed.status is ComparisonStatus.FAILED
    assert failed.error_code == "comparison_error"
    with scan_env.factory() as s:
        assert not s.scalar(
            text("SELECT count(*) FROM comparison_records WHERE comparison_id = :c"),
            {"c": comparison.id},
        )
    assert not scan_env.worker(role=WorkerRole.SCANS).compare_once()  # not retried


def test_comparison_waits_for_in_flight_triage(
    scan_env: ScanEnv, retest_b: dict[str, uuid.UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Findings are share-locked while the comparison reads them: a triage
    holding a finding's lock makes the comparison wait at that read, before it
    computes or writes anything."""
    comparison, _ = request_comparison(scan_env, retest_b["b"], retest_b["scan_b"])
    with scan_env.factory() as s:
        finding_id = s.scalar(
            select(Finding.id).where(Finding.scan_id == retest_b["scan_a"]).limit(1)
        )
    assert finding_id is not None

    def reached_classify(*_: Any) -> Any:
        raise AssertionError("the comparison read findings without waiting for the triage")

    with scan_env.factory() as holder:
        AnalysisRepository(holder).get_finding_for_update(finding_id)  # triage in progress
        with monkeypatch.context() as m, scan_env.factory() as s:
            m.setattr(comparison_service, "classify", reached_classify)
            locked = ComparisonRepository(s).get_for_update(comparison.id, skip_locked=False)
            assert locked is not None
            s.execute(text("SET LOCAL lock_timeout = '300ms'"))
            with pytest.raises(OperationalError, match="lock timeout"):
                comparison_service.execute_comparison(s, locked, datetime.now(UTC))
        holder.rollback()
    assert scan_env.worker(role=WorkerRole.SCANS).compare_once()


# --- database guarantees ------------------------------------------------------------------


def _rejected(env: ScanEnv, sql: str, params: Mapping[str, Any], match: str) -> None:
    with env.factory() as s, pytest.raises((IntegrityError, DBAPIError), match=match):
        s.execute(text(sql), dict(params))
        s.flush()


@pytest.fixture
def compared(scan_env: ScanEnv, retest_b: dict[str, uuid.UUID]) -> dict[str, Any]:
    comparison, _ = request_comparison(scan_env, retest_b["b"], retest_b["scan_b"])
    assert scan_env.worker(role=WorkerRole.SCANS).compare_once()
    with scan_env.factory() as s:
        fixed = s.scalars(
            select(ComparisonRecord).where(
                ComparisonRecord.comparison_id == comparison.id, ComparisonRecord.state == "fixed"
            )
        ).first()
        assert fixed is not None
        s.expunge(fixed)
    return {**retest_b, "comparison": comparison.id, "fixed": fixed}


@pytest.mark.parametrize(
    ("sql", "match"),
    [
        ("UPDATE comparisons SET summary = '{}'::jsonb WHERE id = :c", "immutable"),
        ("UPDATE comparisons SET status = 'failed', error_code = 'x' WHERE id = :c", "immutable"),
        ("DELETE FROM comparisons WHERE id = :c", "cannot be deleted"),
        ("UPDATE comparison_records SET state = 'fixed' WHERE comparison_id = :c", "immutable"),
        ("DELETE FROM comparison_records WHERE comparison_id = :c", "immutable"),
        ("DELETE FROM comparison_coverage_evidence WHERE comparison_id = :c", "immutable"),
    ],
)
def test_completed_comparisons_are_immutable(
    scan_env: ScanEnv, compared: dict[str, Any], sql: str, match: str
) -> None:
    _rejected(scan_env, sql, {"c": compared["comparison"]}, match)


def test_retest_links_are_immutable(scan_env: ScanEnv, compared: dict[str, Any]) -> None:
    _rejected(
        scan_env,
        "UPDATE assessments SET baseline_scan_id = :s WHERE id = :b",
        {"s": compared["scan_b"], "b": compared["b"]},
        "retest relationship is immutable",
    )
    _rejected(
        scan_env,
        "UPDATE assessments SET retest_of_assessment_id = NULL, baseline_scan_id = NULL "
        "WHERE id = :b",
        {"b": compared["b"]},
        "retest relationship is immutable",
    )


def test_retest_parent_must_share_the_target(scan_env: ScanEnv, compared: dict[str, Any]) -> None:
    # Cancelled, so the one-live-retest index does not apply: only the
    # same-target foreign key decides.
    other_target = scan_env.target()
    with scan_env.factory() as s:
        auth = s.scalar(
            text("SELECT current_authorization_id FROM targets WHERE id = :t"), {"t": other_target}
        )
    _rejected(
        scan_env,
        "INSERT INTO assessments (id, target_id, authorization_id, name, status, "
        "retest_of_assessment_id, baseline_scan_id, created_by_user_id) VALUES "
        "(gen_random_uuid(), :t, :z, 'x', 'cancelled', :a, :s, "
        "(SELECT created_by_user_id FROM assessments WHERE id = :a))",
        {"t": other_target, "z": auth, "a": compared["a"], "s": compared["scan_a"]},
        "fk_assessments_retest_of",
    )


def _queued_comparison(env: ScanEnv, compared: dict[str, Any], **overrides: Any) -> uuid.UUID:
    """A second, queued comparison row for the same retest (another policy
    version), inserted directly so records can be probed against it."""
    with env.factory() as s:
        row = dict(
            s.execute(
                text("SELECT * FROM comparisons WHERE id = :c"), {"c": compared["comparison"]}
            )
            .mappings()
            .one()
        )
        new_id = uuid.uuid4()
        values = {
            k: row[k]
            for k in (
                "target_id", "baseline_assessment_id", "baseline_scan_id", "baseline_run_id",
                "current_assessment_id", "current_scan_id", "current_run_id",
            )
        }  # fmt: skip
        values.update(overrides)
        s.execute(
            text(
                "INSERT INTO comparisons (id, target_id, baseline_assessment_id, "
                "baseline_scan_id, baseline_run_id, current_assessment_id, current_scan_id, "
                "current_run_id, policy_version) VALUES (:id, :target_id, "
                ":baseline_assessment_id, :baseline_scan_id, :baseline_run_id, "
                ":current_assessment_id, :current_scan_id, :current_run_id, 'cmp-99')"
            ),
            {"id": new_id, **values},
        )
        s.commit()
        return new_id


def test_comparisons_require_the_retest_relationship_and_one_target(
    scan_env: ScanEnv, compared: dict[str, Any]
) -> None:
    # Swapping baseline and current: the "current" assessment is not a retest
    # of the "baseline" one.
    with scan_env.factory() as s, pytest.raises(IntegrityError, match="fk_comparisons_retest"):
        s.execute(
            text(
                "INSERT INTO comparisons (id, target_id, baseline_assessment_id, "
                "baseline_scan_id, baseline_run_id, current_assessment_id, current_scan_id, "
                "current_run_id, policy_version) SELECT gen_random_uuid(), target_id, "
                "current_assessment_id, current_scan_id, current_run_id, baseline_assessment_id, "
                "baseline_scan_id, baseline_run_id, 'cmp-98' FROM comparisons WHERE id = :c"
            ),
            {"c": compared["comparison"]},
        )
    other_target = scan_env.target()
    with pytest.raises(IntegrityError, match="fk_comparisons_baseline_scan"):
        _queued_comparison(scan_env, compared, target_id=other_target)


def test_records_cannot_cross_scans_or_identities(
    scan_env: ScanEnv, compared: dict[str, Any]
) -> None:
    probe = _queued_comparison(scan_env, compared)
    fixed = compared["fixed"]
    with scan_env.factory() as s:
        current_finding = s.scalar(
            select(Finding.id).where(Finding.scan_id == compared["scan_b"]).limit(1)
        )
        current_fp = s.scalar(select(Finding.fingerprint).where(Finding.id == current_finding))
    insert = (
        "INSERT INTO comparison_records (comparison_id, fingerprint, baseline_scan_id, "
        "current_scan_id, rule_id, state, reasons, baseline_finding_id, current_finding_id, "
        "baseline_triage, current_triage) VALUES (:c, :fp, :bs, :cs, 'SV-HDR-002', :state, "
        "'{}', :bf, :cf, :bt, :ct)"
    )
    base = {
        "c": probe, "fp": fixed.fingerprint, "bs": compared["scan_a"], "cs": compared["scan_b"],
        "state": "fixed", "bf": fixed.baseline_finding_id, "cf": None, "bt": "open", "ct": None,
    }  # fmt: skip
    # A current-scan finding presented as the baseline finding (cross-scan).
    _rejected(scan_env, insert, {**base, "bf": current_finding, "fp": current_fp},
              "fk_comparison_records_baseline_finding")  # fmt: skip
    # The right finding under another fingerprint (cross-identity).
    _rejected(scan_env, insert, {**base, "fp": "0" * 64}, "fk_comparison_records_baseline_finding")
    # A record on scans other than its comparison's.
    _rejected(
        scan_env, insert, {**base, "cs": compared["scan_a"]}, "fk_comparison_records_comparison"
    )
    # State and presence must agree; a false positive is never fixed.
    _rejected(scan_env, insert, {**base, "state": "new"}, "new_has_only_current")
    _rejected(scan_env, insert, {**base, "bt": "false_positive"}, "false_positive_never_fixed")


def test_coverage_evidence_is_pinned_to_the_current_scan(
    scan_env: ScanEnv, compared: dict[str, Any]
) -> None:
    probe = _queued_comparison(scan_env, compared)
    fixed = compared["fixed"]
    with scan_env.factory() as s:
        s.execute(
            text(
                "INSERT INTO comparison_records (comparison_id, fingerprint, baseline_scan_id, "
                "current_scan_id, rule_id, state, reasons, baseline_finding_id, baseline_triage) "
                "VALUES (:c, :fp, :bs, :cs, :r, 'fixed', '{}', :bf, 'open')"
            ),
            {"c": probe, "fp": fixed.fingerprint, "bs": compared["scan_a"],
             "cs": compared["scan_b"], "r": fixed.rule_id, "bf": fixed.baseline_finding_id},
        )  # fmt: skip
        s.commit()
        baseline_evidence = s.scalar(
            text("SELECT id FROM evidence WHERE scan_id = :s LIMIT 1"), {"s": compared["scan_a"]}
        )
        current_evidence = s.scalars(
            text("SELECT id FROM evidence WHERE scan_id = :s ORDER BY id"),
            {"s": compared["scan_b"]},
        ).all()
    insert = "INSERT INTO comparison_coverage_evidence VALUES (:c, :fp, :s, :e)"
    params = {"c": probe, "fp": fixed.fingerprint, "s": compared["scan_b"]}
    _rejected(scan_env, insert, {**params, "e": baseline_evidence},
              "fk_comparison_coverage_evidence_evidence")  # fmt: skip
    _rejected(scan_env, insert, {**params, "s": compared["scan_a"], "e": baseline_evidence},
              "fk_comparison_coverage_evidence_record")  # fmt: skip
    # At most 25 per record (the lab scan has fewer; the trigger counts rows).
    with scan_env.factory() as s:
        for evidence_id in current_evidence:
            s.execute(text(insert), {**params, "e": evidence_id})
        s.commit()
    assert len(current_evidence) < 25
    with scan_env.factory() as s:
        count = s.scalar(
            text("SELECT count(*) FROM comparison_coverage_evidence WHERE comparison_id = :c"),
            {"c": probe},
        )
    assert count == len(current_evidence)


def test_coverage_evidence_limit_is_enforced(scan_env: ScanEnv, compared: dict[str, Any]) -> None:
    with scan_env.factory() as s:
        trigger = s.scalar(
            text("SELECT prosrc FROM pg_proc WHERE proname = 'guard_comparison_coverage_changes'")
        )
    assert trigger is not None and ">= 25" in trigger


def test_cited_findings_cannot_be_deleted(scan_env: ScanEnv, compared: dict[str, Any]) -> None:
    _rejected(
        scan_env,
        "DELETE FROM findings WHERE id = :f",
        {"f": compared["fixed"].baseline_finding_id},
        "comparison_records",
    )


def test_one_live_retest_index(scan_env: ScanEnv, compared: dict[str, Any]) -> None:
    with scan_env.factory() as s:
        auth = s.scalar(
            text("SELECT authorization_id FROM assessments WHERE id = :b"), {"b": compared["b"]}
        )
    _rejected(
        scan_env,
        "INSERT INTO assessments (id, target_id, authorization_id, name, status, "
        "retest_of_assessment_id, baseline_scan_id, created_by_user_id) VALUES "
        "(gen_random_uuid(), :t, :z, 'x', 'planned', :a, :s, "
        "(SELECT created_by_user_id FROM assessments WHERE id = :a))",
        {"t": compared["target"], "z": auth, "a": compared["a"], "s": compared["scan_a"]},
        "uq_assessments_one_live_retest",
    )


# --- API -------------------------------------------------------------------------------------


def test_retest_and_comparison_api(
    scan_env: ScanEnv, baseline: dict[str, uuid.UUID], committed_api: TestClient
) -> None:
    api = committed_api
    a = baseline["a"]
    created = api.post(f"/api/v1/assessments/{a}/retests", json={"name": "Retest B"})
    assert created.status_code == 201, created.text
    b = created.json()
    assert b["retest_of_assessment_id"] == str(a)
    assert b["baseline_scan_id"] == str(baseline["scan_a"])
    duplicate = api.post(f"/api/v1/assessments/{a}/retests", json={"name": "Again"})
    assert duplicate.status_code == 409 and duplicate.json()["reason"] == "retest_exists"
    assert [r["id"] for r in api.get(f"/api/v1/assessments/{a}/retests").json()] == [b["id"]]
    assert (
        api.post(f"/api/v1/assessments/{a}/retests", json={"name": "x", "extra": 1}).status_code
        == 422
    )

    bid = uuid.UUID(b["id"])
    assert api.post(f"/api/v1/assessments/{bid}/start").status_code == 200
    site_b(scan_env.site)
    scan_b = run_scan(scan_env, bid)
    url = f"/api/v1/assessments/{bid}/comparisons"
    first = api.post(url, json={"scan_id": str(scan_b)})
    assert first.status_code == 202 and first.json()["status"] == "queued"
    second = api.post(url, json={"scan_id": str(scan_b)})
    assert second.status_code == 200 and second.json()["id"] == first.json()["id"]
    cid = first.json()["id"]
    assert api.get(f"/api/v1/comparisons/{cid}/records").status_code == 409  # not computed yet
    assert scan_env.worker(role=WorkerRole.SCANS).compare_once()

    detail = api.get(f"/api/v1/comparisons/{cid}").json()
    assert detail["status"] == "completed" and detail["summary"]["policy_version"] == "cmp-1"
    records = api.get(f"/api/v1/comparisons/{cid}/records", params={"limit": 100}).json()
    assert sum(detail["summary"]["states"].values()) == len(records)
    fixed = api.get(f"/api/v1/comparisons/{cid}/records", params={"state": "fixed"}).json()
    assert fixed and all(r["state"] == "fixed" and r["coverage_evidence_ids"] for r in fixed)
    assert all(r["current_finding_id"] is None and r["baseline_evidence_ids"] for r in fixed)
    one = api.get(f"/api/v1/comparisons/{cid}/records/{fixed[0]['fingerprint']}").json()
    assert one == fixed[0]
    assert (
        api.get(f"/api/v1/comparisons/{cid}/records", params={"state": "bogus"}).status_code == 422
    )
    # A fingerprint that cannot exist is simply not found (authorization
    # resolves the record before path validation; Phase 9 M4).
    assert api.get(f"/api/v1/comparisons/{cid}/records/xyz").status_code == 404
    assert api.get(f"/api/v1/comparisons/{cid}/records/{'0' * 64}").status_code == 404
    assert [c["id"] for c in api.get(url).json()] == [cid]
    lineage = api.get(f"/api/v1/assessments/{bid}/lineage").json()
    assert [e["assessment_id"] for e in lineage] == [str(a), str(bid)]
    assert api.get(f"/api/v1/comparisons/{uuid.uuid4()}").status_code == 404
    assert api.get(f"/api/v1/assessments/{uuid.uuid4()}/lineage").status_code == 404
    not_retest = api.post(
        f"/api/v1/assessments/{a}/comparisons", json={"scan_id": str(baseline["scan_a"])}
    )
    assert not_retest.status_code == 409 and not_retest.json()["reason"] == "not_a_retest"
