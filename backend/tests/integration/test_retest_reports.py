"""Phase 7 retest reports end to end against a 127.0.0.1 lab site: golden
A -> B and B -> C reports, rule-version mismatch, eligibility, idempotency,
database guarantees, worker behaviour, triage locking, historical
immutability and the API."""

import json
import threading
import uuid
from collections.abc import Iterable, Mapping
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sentinel_analysis import analyze
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError

from app.api.deps import get_finding_service, get_report_service, get_retest_report_service
from app.core.clock import utc_now
from app.core.errors import NotFoundError, RetestReportNotAllowedError
from app.models import (
    ComparisonRecord,
    Finding,
    Report,
    ReportArtifact,
    RetestReport,
    RetestReportArtifact,
)
from app.models.enums import ComparisonStatus, FindingStatus, ReportStatus
from app.repositories import AnalysisRepository, RetestReportRepository
from app.schemas.report import ReportCreate
from app.schemas.retest_report import RetestReportCreate
from app.services import analysis as analysis_service
from app.services import comparisons as comparison_service
from app.worker import WorkerRole
from sentinel_reports import Artifact
from sentinel_reports.retest import (
    render_retest_report,
    retest_content_digest,
    retest_snapshot_digest,
    validate_retest_snapshot,
)
from tests.integration.scan_support import ScanEnv
from tests.integration.test_analysis import committed_api
from tests.integration.test_retests import (
    baseline,
    broken_rule,
    complete,
    create_retest,
    load_comparison,
    mark_false_positive,
    narrow_scope,
    request_comparison,
    run_scan,
    site_b,
    site_c,
    start,
)

pytestmark = pytest.mark.integration

__all__ = ["baseline", "committed_api"]  # fixtures re-exported for this module

LOCAL = ["json", "html"]  # PDF needs Pango; covered by the pdf-marked test
LAB_SECRET = "LAB-SECRET"  # noqa: S105  # cookie value set by the lab site, must never be stored


def compute(env: ScanEnv) -> None:
    assert env.worker(role=WorkerRole.SCANS).compare_once()


def request_report(
    env: ScanEnv,
    assessment_id: uuid.UUID,
    comparison_id: uuid.UUID,
    *,
    formats: Iterable[str] = LOCAL,
    **kw: Any,
) -> tuple[uuid.UUID, bool]:
    with env.factory() as s:
        data = RetestReportCreate.model_validate(
            {"title": "Retest report", "formats": list(formats), **kw}
        )
        report, created = get_retest_report_service(s, utc_now).create(
            assessment_id, comparison_id, data, actor=env.actor
        )
        return report.id, created


def load(env: ScanEnv, report_id: uuid.UUID) -> RetestReport:
    with env.factory() as s:
        report = s.get(RetestReport, report_id)
        assert report is not None
        s.expunge(report)
        return report


def artifacts(env: ScanEnv, report_id: uuid.UUID) -> dict[str, RetestReportArtifact]:
    with env.factory() as s:
        rows = s.scalars(
            select(RetestReportArtifact).where(RetestReportArtifact.report_id == report_id)
        ).all()
        s.expunge_all()
        return {a.format: a for a in rows}


def render_worker(env: ScanEnv, name: str = "report-worker", **kw: Any) -> Any:
    return env.worker(name, role=WorkerRole.REPORTS, **kw)


@pytest.fixture
def chain(
    scan_env: ScanEnv, baseline: dict[str, uuid.UUID], monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    """A -> B -> C with completed comparisons, as in the Phase 6 golden chain."""
    env = scan_env
    mark_false_positive(env, baseline["scan_a"], "SV-COR-001")
    b = create_retest(env, baseline["a"], name="Retest B")
    start(env, b)
    site_b(env.site)
    scan_b = run_scan(env, b)
    complete(env, b)
    cmp_b, _ = request_comparison(env, b, scan_b)
    compute(env)
    narrow_scope(env, baseline["target"], ["/admin", "/error"])
    c = create_retest(env, b, name="Retest C")
    start(env, c)
    site_c(env.site)
    with monkeypatch.context() as m:
        m.setattr(analysis_service, "analyze", lambda obs: analyze(obs, broken_rule("SV-CKE-001")))
        scan_c = run_scan(env, c)
    complete(env, c)
    cmp_c, _ = request_comparison(env, c, scan_c)
    compute(env)
    assert load_comparison(env, cmp_c.id).status is ComparisonStatus.COMPLETED
    return {**baseline, "b": b, "scan_b": scan_b, "cmp_b": cmp_b.id, "c": c, "scan_c": scan_c,
            "cmp_c": cmp_c.id}  # fmt: skip


def snapshot_states(snap: Mapping[str, Any]) -> dict[str, str]:
    return {r["fingerprint"]: r["state"] for r in snap["records"]}


def db_states(env: ScanEnv, comparison_id: uuid.UUID) -> dict[str, str]:
    with env.factory() as s:
        return {
            r.fingerprint: str(r.state)
            for r in s.scalars(
                select(ComparisonRecord).where(ComparisonRecord.comparison_id == comparison_id)
            )
        }


# --- golden reports ------------------------------------------------------------------------


def test_golden_a_to_b_report(scan_env: ScanEnv, chain: dict[str, Any]) -> None:
    env = scan_env
    report_id, created = request_report(env, chain["b"], chain["cmp_b"], kind="final")
    assert created
    queued = load(env, report_id)
    assert queued.status is ReportStatus.QUEUED
    validate_retest_snapshot(queued.snapshot)
    assert queued.snapshot_sha256 == retest_snapshot_digest(queued.snapshot)
    assert queued.content_sha256 == retest_content_digest(queued.snapshot)
    snap = queued.snapshot

    # States are copied exactly from the persisted comparison.
    assert snapshot_states(snap) == db_states(env, chain["cmp_b"])
    stored_summary = load_comparison(env, chain["cmp_b"]).summary
    assert stored_summary is not None
    assert snap["comparison"]["summary"] == stored_summary["states"]
    counts = snap["comparison"]["summary"]
    assert counts["fixed"] == 3 and counts["dismissed"] == 1 and counts["new"] == 1

    records = {(r["rule_id"], r["state"]): r for r in snap["records"]}
    fixed = [r for r in snap["records"] if r["state"] == "fixed"]
    current_ids = {e["id"] for e in snap["evidence"] if e["role"] == "current"}
    for r in fixed:
        assert r["coverage_evidence_ids"] and set(r["coverage_evidence_ids"]) <= current_ids
    dismissed = records[("SV-COR-001", "dismissed")]
    assert dismissed["triage_when_compared"]["baseline"] == "false_positive"
    assert dismissed["triage_when_reported"]["baseline"] == "false_positive"
    for e in snap["evidence"]:
        expected = str(chain["scan_a"]) if e["role"] == "baseline" else str(chain["scan_b"])
        assert e["scan_id"] == expected

    assert snap["scope_change"]["narrower"] is False
    assert [step["assessment"]["name"] for step in snap["lineage"]] == ["Assessment", "Retest B"]
    assert "scope_narrowed" not in snap["limitations"]

    assert render_worker(env).run_once()
    report = load(env, report_id)
    assert report.status is ReportStatus.COMPLETED, report.error_code
    files = artifacts(env, report_id)
    fresh = {a.format: a for a in render_retest_report(report.snapshot, LOCAL)}
    for fmt, stored in files.items():
        assert stored.content == fresh[fmt].content and stored.sha256 == fresh[fmt].sha256
    document = json.loads(files["json"].content)
    assert document["schema_version"] == "sentinelvapt.retest-report-document/1"
    assert document["derived"]["counts"] == counts
    html = files["html"].content.decode()
    for section_id in ("state-new", "state-fixed", "state-dismissed", "state-not_retested"):
        assert f'id="{section_id}"' in html
    everything = json.dumps(report.snapshot) + "".join(
        a.content.decode("utf-8", "replace") for a in files.values()
    )
    assert LAB_SECRET not in everything

    # Evidence links mirror the snapshot, bound to the right scans.
    with env.factory() as s:
        links = s.execute(
            text(
                "SELECT role, evidence_id::text, coalesce(baseline_scan_id, current_scan_id) "
                "FROM retest_report_evidence WHERE report_id = :r"
            ),
            {"r": report_id},
        ).all()
    assert {(role, eid) for role, eid, _ in links} == {
        (e["role"], e["id"]) for e in snap["evidence"]
    }


def test_golden_b_to_c_report(scan_env: ScanEnv, chain: dict[str, Any]) -> None:
    env = scan_env
    report_id, _ = request_report(env, chain["c"], chain["cmp_c"], kind="final")
    snap = load(env, report_id).snapshot
    assert snapshot_states(snap) == db_states(env, chain["cmp_c"])
    reopened = [r for r in snap["records"] if r["state"] == "reopened"]
    assert len(reopened) == 2
    for r in reopened:
        assert r["history"] == {
            "comparison_id": str(chain["cmp_b"]),
            "assessment_id": str(chain["b"]),
            "assessment_name": "Retest B",
            "state": "fixed",
        }
    not_retested = [r for r in snap["records"] if r["state"] == "not_retested"]
    assert [r["reasons"] for r in not_retested] == [["out_of_scope"]]
    not_comparable = [r for r in snap["records"] if r["state"] == "not_comparable"]
    assert [(r["rule_id"], r["reasons"]) for r in not_comparable] == [
        ("SV-CKE-001", ["rule_error"])
    ]

    # The retest's own (narrower) authorization is authoritative and disclosed.
    assert snap["authorization"]["retest"]["scope"]["excluded_paths"] == ["/admin", "/error"]
    assert snap["authorization"]["baseline"]["scope"]["excluded_paths"] == ["/admin"]
    assert snap["scope_change"]["narrower"] is True
    assert snap["scope_change"]["exclusions_added"] == ["/error"]
    assert {"scope_narrowed", "rule_errors"} <= set(snap["limitations"])

    # A -> B -> C lineage.
    lineage = snap["lineage"]
    assert [s["assessment"]["name"] for s in lineage] == ["Assessment", "Retest B", "Retest C"]
    assert lineage[0]["comparison"] is None
    assert lineage[1]["comparison"]["id"] == str(chain["cmp_b"])
    assert lineage[2]["comparison"]["id"] == str(chain["cmp_c"])

    assert render_worker(env).run_once()
    html = artifacts(env, report_id)["html"].content.decode()
    assert "narrower than the baseline scope" in html
    assert str(chain["cmp_b"]) in html[html.index('id="state-reopened"') :]
    assert "NOT evidence of remediation" in html


def test_rule_version_mismatch_is_reported(
    scan_env: ScanEnv, baseline: dict[str, uuid.UUID]
) -> None:
    """The retest run evaluated another version of SV-HDR-002 (simulated by
    editing its recorded rule versions before comparing): its baseline finding
    is not comparable, and the report lists the version difference."""
    env = scan_env
    b = create_retest(env, baseline["a"])
    start(env, b)
    site_b(env.site)
    scan_b = run_scan(env, b)
    complete(env, b)
    with env.factory() as s:
        s.execute(
            text(
                "UPDATE analysis_runs SET rule_versions = ("
                "SELECT jsonb_agg(CASE WHEN e->>'rule_id' = 'SV-HDR-002' "
                "THEN jsonb_build_object('rule_id', 'SV-HDR-002', 'version', 2) ELSE e END) "
                "FROM jsonb_array_elements(rule_versions) e) WHERE scan_id = :s"
            ),
            {"s": scan_b},
        )
        s.commit()
    cmp_b, _ = request_comparison(env, b, scan_b)
    compute(env)
    report_id, _ = request_report(env, b, cmp_b.id)
    snap = load(env, report_id).snapshot
    hdr = next(r for r in snap["records"] if r["rule_id"] == "SV-HDR-002")
    assert (hdr["state"], hdr["reasons"]) == ("not_comparable", ["rule_version_changed"])
    assert "rule_versions_differ" in snap["limitations"]
    assert render_worker(env).run_once()
    html = artifacts(env, report_id)["html"].content.decode()
    rv = html[html.index('id="rule-versions"') : html.index('id="limitations"')]
    assert "SV-HDR-002" in rv and ">1<" in rv and ">2<" in rv


# --- eligibility and idempotency -----------------------------------------------------------


@pytest.fixture
def retest_b(scan_env: ScanEnv, baseline: dict[str, uuid.UUID]) -> dict[str, Any]:
    b = create_retest(scan_env, baseline["a"])
    start(scan_env, b)
    site_b(scan_env.site)
    scan_b = run_scan(scan_env, b)
    return {**baseline, "b": b, "scan_b": scan_b}


def test_eligibility(
    scan_env: ScanEnv, retest_b: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    env = scan_env
    queued, _ = request_comparison(env, retest_b["b"], retest_b["scan_b"])
    with pytest.raises(RetestReportNotAllowedError) as info:
        request_report(env, retest_b["b"], queued.id)
    assert info.value.reason == "comparison_not_completed"
    compute(env)
    # Final requires the retest assessment to be completed; a draft does not.
    with pytest.raises(RetestReportNotAllowedError) as info:
        request_report(env, retest_b["b"], queued.id, kind="final")
    assert info.value.reason == "assessment_not_completed"
    _, created = request_report(env, retest_b["b"], queued.id, kind="draft")
    assert created
    # Another assessment's comparison is not reachable from this one.
    with pytest.raises(NotFoundError):
        request_report(env, retest_b["a"], queued.id)
    with pytest.raises(NotFoundError):
        request_report(env, retest_b["b"], uuid.uuid4())


def test_failed_comparison_is_not_reportable(
    scan_env: ScanEnv, retest_b: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    comparison, _ = request_comparison(scan_env, retest_b["b"], retest_b["scan_b"])

    def fail(*_: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(comparison_service, "classify", fail)
    compute(scan_env)
    assert load_comparison(scan_env, comparison.id).status is ComparisonStatus.FAILED
    with pytest.raises(RetestReportNotAllowedError) as info:
        request_report(scan_env, retest_b["b"], comparison.id)
    assert info.value.reason == "comparison_not_completed"


def test_identical_requests_return_the_existing_report(
    scan_env: ScanEnv, retest_b: dict[str, Any]
) -> None:
    env = scan_env
    comparison, _ = request_comparison(env, retest_b["b"], retest_b["scan_b"])
    compute(env)
    first, created = request_report(env, retest_b["b"], comparison.id)
    again, created_again = request_report(env, retest_b["b"], comparison.id)
    assert created and not created_again and again == first
    other_title, created = request_report(env, retest_b["b"], comparison.id, title="Another")
    assert created and other_title != first
    # A later triage change is new content: a new report, the old one unchanged.
    with env.factory() as s:
        finding = s.scalars(
            select(Finding).where(Finding.scan_id == retest_b["scan_b"]).limit(1)
        ).one()
        get_finding_service(s, utc_now).triage(
            finding.id, FindingStatus.CONFIRMED, None, actor=env.actor
        )
    after_triage, created = request_report(env, retest_b["b"], comparison.id)
    assert created and after_triage != first
    assert load(env, first).snapshot != load(env, after_triage).snapshot


@pytest.mark.parametrize("attempt", range(3))
def test_concurrent_identical_requests_create_one_report(
    scan_env: ScanEnv, retest_b: dict[str, Any], attempt: int
) -> None:
    comparison, _ = request_comparison(scan_env, retest_b["b"], retest_b["scan_b"])
    compute(scan_env)
    barrier = threading.Barrier(4)
    results: list[tuple[uuid.UUID, bool]] = []
    lock = threading.Lock()

    def request() -> None:
        barrier.wait()
        outcome = request_report(scan_env, retest_b["b"], comparison.id, title=f"T{attempt}")
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=request) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert sum(created for _, created in results) == 1
    assert len({rid for rid, _ in results}) == 1


def test_report_request_waits_for_in_flight_triage(
    scan_env: ScanEnv, retest_b: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    comparison, _ = request_comparison(scan_env, retest_b["b"], retest_b["scan_b"])
    compute(scan_env)
    with scan_env.factory() as s:
        finding_id = s.scalar(
            select(Finding.id).where(Finding.scan_id == retest_b["scan_b"]).limit(1)
        )
    assert finding_id is not None

    def reached(*_: Any, **__: Any) -> Any:
        raise AssertionError("the snapshot read triage without waiting for the triage in flight")

    with scan_env.factory() as holder:
        AnalysisRepository(holder).get_finding_for_update(finding_id)
        with monkeypatch.context() as m, scan_env.factory() as s:
            m.setattr(RetestReportRepository, "insert_if_new", reached)
            s.execute(text("SET LOCAL lock_timeout = '300ms'"))
            data = RetestReportCreate(title="T", formats=["json"])
            with pytest.raises(OperationalError, match="lock timeout"):
                get_retest_report_service(s, utc_now).create(
                    retest_b["b"], comparison.id, data, actor=scan_env.actor
                )
        holder.rollback()


# --- database guarantees -------------------------------------------------------------------


def _rejected(env: ScanEnv, sql: str, params: Mapping[str, Any], match: str) -> None:
    with env.factory() as s, pytest.raises((IntegrityError, DBAPIError), match=match):
        s.execute(text(sql), dict(params))
        s.flush()


def _accepted(env: ScanEnv, sql: str, params: Mapping[str, Any]) -> None:
    """Positive control: the statement succeeds (and is rolled back), so a
    rejection of a variant differing in one column comes from that column."""
    with env.factory() as s:
        s.execute(text(sql), dict(params))
        s.flush()
        s.rollback()


@pytest.fixture
def completed(scan_env: ScanEnv, chain: dict[str, Any]) -> dict[str, Any]:
    report_id, _ = request_report(scan_env, chain["b"], chain["cmp_b"])
    assert render_worker(scan_env).run_once()
    assert load(scan_env, report_id).status is ReportStatus.COMPLETED
    return {**chain, "report": report_id}


@pytest.mark.parametrize(
    ("sql", "match"),
    [
        ("UPDATE retest_reports SET title = 'x' WHERE id = :r", "immutable"),
        ("UPDATE retest_reports SET snapshot = '{}'::jsonb WHERE id = :r", "immutable"),
        ("DELETE FROM retest_reports WHERE id = :r", "cannot be deleted"),
        ("UPDATE retest_report_artifacts SET renderer = 'x' WHERE report_id = :r", "immutable"),
        ("DELETE FROM retest_report_artifacts WHERE report_id = :r", "immutable"),
        ("DELETE FROM retest_report_evidence WHERE report_id = :r", "immutable"),
    ],
)
def test_completed_retest_reports_are_immutable(
    scan_env: ScanEnv, completed: dict[str, Any], sql: str, match: str
) -> None:
    _rejected(scan_env, sql, {"r": completed["report"]}, match)


def _copy_report_sql(**changes: str) -> str:
    columns = (
        "number", "comparison_id", "target_id", "baseline_assessment_id", "baseline_scan_id",
        "current_assessment_id", "current_scan_id", "kind", "title", "prepared_by",
        "requested_by_user_id", "classification", "formats", "template_id", "template_version",
        "template_hash", "schema_version", "snapshot", "snapshot_sha256", "content_sha256",
    )  # fmt: skip
    values = [changes.get(c, c) for c in columns]
    return (
        f"INSERT INTO retest_reports (id, {', '.join(columns)}) "  # noqa: S608  # test constants
        f"SELECT gen_random_uuid(), {', '.join(values)} FROM retest_reports WHERE id = :r"
    )


def test_reports_require_a_completed_comparison(
    scan_env: ScanEnv, completed: dict[str, Any]
) -> None:
    env = scan_env
    # A queued comparison: create one for a new retest of C.
    d = create_retest(env, completed["c"])
    start(env, d)
    scan_d = run_scan(env, d)
    cmp_d, _ = request_comparison(env, d, scan_d)
    with env.factory() as s:
        row = s.execute(
            text(
                "SELECT baseline_assessment_id, baseline_scan_id, current_assessment_id, "
                "current_scan_id FROM comparisons WHERE id = :c"
            ),
            {"c": cmp_d.id},
        ).one()
    sql = _copy_report_sql(
        number="900001",
        comparison_id=f"'{cmp_d.id}'",
        baseline_assessment_id=f"'{row[0]}'",
        baseline_scan_id=f"'{row[1]}'",
        current_assessment_id=f"'{row[2]}'",
        current_scan_id=f"'{row[3]}'",
        content_sha256="repeat('1', 64)",
    )
    _rejected(env, sql, {"r": completed["report"]}, "completed comparison")


def test_report_scans_must_belong_to_the_report_target(
    scan_env: ScanEnv, completed: dict[str, Any]
) -> None:
    """Both scan foreign keys carry the report's target_id: a report whose
    target differs from its scans' target is refused by those keys."""
    env = scan_env
    params = {"r": completed["report"]}
    _accepted(env, _copy_report_sql(number="900002", content_sha256="repeat('2', 64)"), params)
    other_target = env.target()
    _rejected(
        env,
        _copy_report_sql(
            number="900003", target_id=f"'{other_target}'", content_sha256="repeat('3', 64)"
        ),
        params,
        r"fk_retest_reports_(baseline|current)_scan",
    )


def test_identical_content_is_stored_once_unless_failed(
    scan_env: ScanEnv, completed: dict[str, Any]
) -> None:
    """The partial unique index: one non-failed report per (comparison, kind,
    content digest); a failed one does not block a new identical report."""
    env = scan_env
    params = {"r": completed["report"]}
    _accepted(env, _copy_report_sql(number="900004", content_sha256="repeat('4', 64)"), params)
    _rejected(env, _copy_report_sql(number="900005"), params, "uq_retest_reports_identical_content")
    probe, created = request_report(env, completed["b"], completed["cmp_b"], title="Dup")
    assert created
    with env.factory() as s:
        s.execute(
            text(
                "UPDATE retest_reports SET status = 'failed', claimed_by = 'w', "
                "claimed_at = now(), "
                "error_code = 'render_error', finished_at = now() WHERE id = :r"
            ),
            {"r": probe},
        )
        s.commit()
    _accepted(env, _copy_report_sql(number="900006"), {"r": probe})


def test_evidence_links_are_bound_to_one_scan_role(
    scan_env: ScanEnv, completed: dict[str, Any]
) -> None:
    env = scan_env
    # A fresh queued report (different title) to probe link inserts against.
    probe, created = request_report(env, completed["b"], completed["cmp_b"], title="Probe")
    assert created
    with env.factory() as s:
        baseline_ev = s.scalar(
            text("SELECT id FROM evidence WHERE scan_id = :s LIMIT 1"), {"s": completed["scan_a"]}
        )
        other_ev = s.scalar(
            text("SELECT id FROM evidence WHERE scan_id = :s LIMIT 1"), {"s": completed["scan_c"]}
        )
    insert = (
        "INSERT INTO retest_report_evidence (report_id, role, evidence_id, baseline_scan_id, "
        "current_scan_id) VALUES (:r, :role, :e, :bs, :cs)"
    )
    base = {"r": probe, "role": "current", "e": baseline_ev, "bs": None, "cs": completed["scan_b"]}
    # Baseline evidence claimed as retest evidence.
    _rejected(env, insert, base, "fk_retest_report_evidence_current_evidence")
    # Evidence of an unrelated scan.
    _rejected(env, insert, {**base, "e": other_ev}, "fk_retest_report_evidence_current_evidence")
    # Role and scan column must agree, exactly one scan column.
    _rejected(env, insert, {**base, "role": "baseline"}, "exactly_one_scan_role")
    _rejected(env, insert, {**base, "bs": completed["scan_a"]}, "exactly_one_scan_role")
    # A scan that is not this report's.
    _rejected(
        env,
        insert,
        {**base, "e": other_ev, "cs": completed["scan_c"]},
        "fk_retest_report_evidence_current_report",
    )


def test_artifact_integrity_and_cited_evidence_protection(
    scan_env: ScanEnv, completed: dict[str, Any]
) -> None:
    env = scan_env
    probe, _ = request_report(env, completed["b"], completed["cmp_b"], title="Probe 2")
    with env.factory() as s:
        s.execute(
            text(
                "UPDATE retest_reports SET status = 'generating', claimed_by = 'w', "
                "claimed_at = now() WHERE id = :r"
            ),
            {"r": probe},
        )
        s.commit()
    _rejected(
        env,
        "INSERT INTO retest_report_artifacts (report_id, format, media_type, content, "
        "size_bytes, sha256, renderer) VALUES (:r, 'json', 'application/json', "
        "'\\x01'::bytea, 1, repeat('0', 64), 'x')",
        {"r": probe},
        "sha256_matches_content",
    )
    _rejected(
        env,
        "UPDATE retest_reports SET status = 'completed', finished_at = now() WHERE id = :r",
        {"r": probe},
        "exactly its requested artifacts",
    )
    with env.factory() as s:
        cited = s.scalar(
            text("SELECT evidence_id FROM retest_report_evidence WHERE report_id = :r LIMIT 1"),
            {"r": completed["report"]},
        )
    with env.factory() as s, pytest.raises(IntegrityError, match="retest_report_evidence"):
        s.execute(text("DELETE FROM finding_evidence WHERE evidence_id = :e"), {"e": cited})
        s.execute(
            text("DELETE FROM comparison_coverage_evidence WHERE evidence_id = :e"), {"e": cited}
        )
        s.execute(text("ALTER TABLE comparison_coverage_evidence DISABLE TRIGGER USER"))
        s.execute(text("DELETE FROM evidence WHERE id = :e"), {"e": cited})


# --- worker --------------------------------------------------------------------------------


def test_roles_and_concurrent_workers(scan_env: ScanEnv, chain: dict[str, Any]) -> None:
    env = scan_env
    ids = [request_report(env, chain["b"], chain["cmp_b"], title=f"R{i}")[0] for i in range(2)]
    assert not env.worker("scans", role=WorkerRole.SCANS).run_once()  # never renders reports
    barrier = threading.Barrier(4)
    done: list[bool] = []
    lock = threading.Lock()

    def work(name: str) -> None:
        worker = render_worker(env, name)
        barrier.wait()
        result = worker.retest_report_once()
        with lock:
            done.append(result)

    threads = [threading.Thread(target=work, args=(f"r{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    while render_worker(env).retest_report_once():
        pass
    for report_id in ids:
        assert load(env, report_id).status is ReportStatus.COMPLETED
        assert set(artifacts(env, report_id)) == {"json", "html"}
    assert done.count(True) <= len(ids)


def test_crash_reaper_and_late_output(scan_env: ScanEnv, chain: dict[str, Any]) -> None:
    env = scan_env
    report_id, _ = request_report(env, chain["b"], chain["cmp_b"])

    class Crash(BaseException):
        """Stands in for the process dying while rendering."""

    def crash(snapshot: Mapping[str, Any], formats: Iterable[str]) -> tuple[Artifact, ...]:
        raise Crash

    crashing = render_worker(env, "crashing", retest_report_renderer=crash)
    claimed = crashing.claim_retest_report(report_id)
    assert claimed is not None
    with pytest.raises(Crash):
        crashing.generate_retest_report(claimed)
    assert load(env, report_id).status is ReportStatus.GENERATING
    assert render_worker(env, "fresh", report_stale_after=3600).reap_stale_retest_reports() == 0
    with env.factory() as s:
        s.execute(text("SELECT pg_sleep(0.05)"))
    assert render_worker(env, "reaper", report_stale_after=0.01).reap_stale_retest_reports() == 1
    report = load(env, report_id)
    assert report.status is ReportStatus.FAILED and report.error_code == "worker_lost"
    late = render_retest_report(claimed.snapshot, LOCAL)
    assert not crashing.finalize_retest_report(claimed, late, None)
    assert artifacts(env, report_id) == {}


def test_render_errors_store_a_code_only(scan_env: ScanEnv, chain: dict[str, Any]) -> None:
    def leaky(snapshot: Mapping[str, Any], formats: Iterable[str]) -> tuple[Artifact, ...]:
        raise RuntimeError(f"boom {LAB_SECRET}")

    report_id, _ = request_report(scan_env, chain["b"], chain["cmp_b"])
    assert render_worker(scan_env, retest_report_renderer=leaky).run_once()
    report = load(scan_env, report_id)
    assert report.status is ReportStatus.FAILED and report.error_code == "render_error"
    assert not render_worker(scan_env).retest_report_once()  # no retry


# --- historical immutability -----------------------------------------------------------------


def test_history_is_untouched(scan_env: ScanEnv, chain: dict[str, Any]) -> None:
    env = scan_env
    # A Phase 5 report of A, generated before any retest report.
    with env.factory() as s:
        p5 = get_report_service(s, utc_now).create(
            chain["a"],
            ReportCreate.model_validate(
                {"scan_id": str(chain["scan_a"]), "title": "A", "formats": LOCAL}
            ),
            actor=env.actor,
        ).id  # fmt: skip
    assert render_worker(env).run_once()
    with env.factory() as s:
        p5_before = {
            a.format: a.content
            for a in s.scalars(select(ReportArtifact).where(ReportArtifact.report_id == p5))
        }
        p5_snapshot = dict(s.get(Report, p5).snapshot)  # type: ignore[union-attr]

    report_id, _ = request_report(env, chain["b"], chain["cmp_b"])
    assert render_worker(env).run_once()
    before = {f: a.content for f, a in artifacts(env, report_id).items()}

    # Later triage and later scans/comparisons change nothing already finalized.
    with env.factory() as s:
        finding = s.scalars(
            select(Finding).where(Finding.scan_id == chain["scan_b"]).limit(1)
        ).one()
        get_finding_service(s, utc_now).triage(
            finding.id, FindingStatus.FALSE_POSITIVE, "later", actor=env.actor
        )
    d = create_retest(env, chain["c"])
    start(env, d)
    run_scan(env, d)
    assert {f: a.content for f, a in artifacts(env, report_id).items()} == before
    rerendered = {
        a.format: a.content for a in render_retest_report(load(env, report_id).snapshot, LOCAL)
    }
    assert rerendered == before
    with env.factory() as s:
        p5_after = {
            a.format: a.content
            for a in s.scalars(select(ReportArtifact).where(ReportArtifact.report_id == p5))
        }
    assert p5_after == p5_before  # Phase 5 artifacts byte-identical
    from sentinel_reports import render_report

    assert {a.format: a.content for a in render_report(p5_snapshot, LOCAL)} == p5_before


# --- API --------------------------------------------------------------------------------------


def test_retest_report_api(
    scan_env: ScanEnv, chain: dict[str, Any], committed_api: TestClient
) -> None:
    api = committed_api
    url = f"/api/v1/assessments/{chain['b']}/comparisons/{chain['cmp_b']}/reports"
    body = {"title": "<script>x</script> retest", "formats": LOCAL}
    first = api.post(url, json=body)
    assert first.status_code == 202, first.text
    again = api.post(url, json=body)
    assert again.status_code == 200 and again.json()["id"] == first.json()["id"]
    report = first.json()
    assert report["number"].startswith("SV-RT-") and "snapshot" not in report
    rid = report["id"]

    assert api.post(url, json={**body, "formats": ["html"]}).status_code == 422
    assert api.post(url, json={**body, "template": "sv-standard@1"}).status_code == 422
    assert api.post(url, json={**body, "extra": 1}).status_code == 422
    wrong = f"/api/v1/assessments/{chain['c']}/comparisons/{chain['cmp_b']}/reports"
    assert api.post(wrong, json=body).status_code == 404
    assert api.get(f"/api/v1/retest-reports/{rid}/artifacts/json").status_code == 409

    assert render_worker(scan_env).run_once()
    detail = api.get(f"/api/v1/retest-reports/{rid}").json()
    assert detail["status"] == "completed"
    assert {a["format"] for a in detail["artifacts"]} == {"json", "html"}
    listed = api.get(f"/api/v1/assessments/{chain['b']}/retest-reports").json()
    assert [r["id"] for r in listed] == [rid]
    download = api.get(f"/api/v1/retest-reports/{rid}/artifacts/html")
    assert download.headers["content-disposition"] == (
        f'attachment; filename="{report["number"]}.html"'
    )
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in download.headers["content-security-policy"]
    assert "<script>x</script>" not in download.text and "&lt;script&gt;" in download.text
    stored = artifacts(scan_env, uuid.UUID(rid))["html"]
    assert download.headers["etag"] == f'"{stored.sha256}"'
    preview = api.get(f"/api/v1/retest-reports/{rid}/preview")
    assert preview.status_code == 200 and "sandbox" in preview.headers["content-security-policy"]
    assert api.get(f"/api/v1/retest-reports/{rid}/artifacts/pdf").status_code == 404
    assert api.get(f"/api/v1/retest-reports/{uuid.uuid4()}").status_code == 404
    templates = api.get("/api/v1/retest-report-templates").json()
    assert [(t["id"], t["version"]) for t in templates] == [("sv-retest", 1)]
    assert detail["template_hash"] == templates[0]["sha256"]
    # The Phase 5 template list is unchanged.
    assert [(t["id"], t["version"]) for t in api.get("/api/v1/report-templates").json()] == [
        ("sv-standard", 1)
    ]


# --- PDF -----------------------------------------------------------------------------------


@pytest.mark.pdf
def test_golden_retest_report_with_pdf(scan_env: ScanEnv, chain: dict[str, Any]) -> None:
    import io

    from pypdf import PdfReader

    report_id, _ = request_report(
        scan_env, chain["c"], chain["cmp_c"], formats=["json", "html", "pdf"]
    )
    assert render_worker(scan_env).run_once()
    report = load(scan_env, report_id)
    assert report.status is ReportStatus.COMPLETED, report.error_code
    pdf = artifacts(scan_env, report_id)["pdf"]
    (fresh,) = render_retest_report(report.snapshot, ["pdf"])
    assert pdf.content == fresh.content
    text_content = "\n".join(
        page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf.content)).pages
    )
    assert "Reopened findings" in text_content and "Not retested" in text_content
    assert LAB_SECRET not in text_content
