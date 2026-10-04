"""Phase 5 reports end to end: 127.0.0.1 lab scan -> analysis -> report request
(snapshot) -> report worker (render) -> artifacts and API, plus the database's
immutability guarantees, worker concurrency and failure handling."""

import json
import threading
import uuid
from collections.abc import Iterable, Mapping
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError

from app.api.deps import get_assessment_service, get_finding_service, get_report_service
from app.core.clock import utc_now
from app.core.errors import NotFoundError
from app.models import Report, ReportArtifact
from app.models.enums import FindingStatus, ReportStatus
from app.repositories import AnalysisRepository, ReportRepository
from app.schemas.report import ReportCreate
from app.worker import WorkerRole
from sentinel_reports import (
    Artifact,
    ArtifactTooLarge,
    canonical_json,
    content_digest,
    render_report,
    snapshot_digest,
    validate_snapshot,
)
from tests.integration.scan_support import ScanEnv
from tests.integration.test_analysis import (
    SESSION_SECRET,
    committed_api,
    findings_of,
    golden_site,
    scan_and_analyse,
)

pytestmark = pytest.mark.integration

__all__ = ["committed_api"]  # fixture re-exported for this module

CSRF_SECRET = "GOLDEN-CSRF-SECRET"  # noqa: S105  # lab fixture value, must never be stored
LOCAL_FORMATS = ["json", "html"]  # PDF needs Pango; covered by the pdf-marked tests


def golden_report_site(env: ScanEnv) -> None:
    golden_site(env.site)
    # The error page (whose evidence gets an excerpt) also carries a secret
    # that the scanner must redact before anything is stored.
    env.site.html(
        "/error",
        "<title>Error</title><pre>Traceback (most recent call last):\n"
        '  File "/srv/app.py", line 1</pre>'
        f'<form><input type="hidden" name="csrf_token" value="{CSRF_SECRET}"></form>',
        status=500,
    )


def assessment_of(env: ScanEnv, scan_id: uuid.UUID) -> uuid.UUID:
    return env.get_scan(scan_id).assessment_id


def request_report(
    env: ScanEnv, scan_id: uuid.UUID, *, formats: Iterable[str] = LOCAL_FORMATS, **kw: Any
) -> uuid.UUID:
    with env.factory() as s:
        data = ReportCreate.model_validate(
            {
                "scan_id": str(scan_id),
                "title": "Golden lab assessment",
                "prepared_by": "Tester",
                "formats": list(formats),
                **kw,
            }
        )
        return get_report_service(s, utc_now).create(assessment_of(env, scan_id), data).id


def report_worker(env: ScanEnv, name: str = "report-worker", **kw: Any) -> Any:
    return env.worker(name, role=WorkerRole.REPORTS, **kw)


def load(env: ScanEnv, report_id: uuid.UUID) -> Report:
    with env.factory() as s:
        report = s.get(Report, report_id)
        assert report is not None
        s.expunge(report)
        return report


def artifacts(env: ScanEnv, report_id: uuid.UUID) -> dict[str, ReportArtifact]:
    with env.factory() as s:
        rows = s.scalars(select(ReportArtifact).where(ReportArtifact.report_id == report_id)).all()
        s.expunge_all()
        return {a.format: a for a in rows}


def complete_assessment(env: ScanEnv, assessment_id: uuid.UUID) -> None:
    with env.factory() as s:
        get_assessment_service(s, utc_now).complete(assessment_id)


@pytest.fixture
def golden(scan_env: ScanEnv) -> uuid.UUID:
    golden_report_site(scan_env)
    return scan_and_analyse(scan_env)


# --- golden end-to-end ------------------------------------------------------------------


def test_golden_report_end_to_end(scan_env: ScanEnv, golden: uuid.UUID) -> None:
    report_id = request_report(scan_env, golden)
    queued = load(scan_env, report_id)
    assert queued.status is ReportStatus.QUEUED
    assert queued.number >= 1
    validate_snapshot(queued.snapshot)
    assert queued.snapshot_sha256 == snapshot_digest(queued.snapshot)
    assert queued.content_sha256 == content_digest(queued.snapshot)

    assert report_worker(scan_env).run_once()
    report = load(scan_env, report_id)
    assert report.status is ReportStatus.COMPLETED
    assert report.error_code is None and report.finished_at is not None

    files = artifacts(scan_env, report_id)
    assert set(files) == {"json", "html"}
    expected = {a.format: a for a in render_report(report.snapshot, LOCAL_FORMATS)}
    for fmt, stored in files.items():
        # Stored bytes equal a fresh render of the stored snapshot (determinism),
        # and the stored hash is the hash of the stored bytes.
        assert stored.content == expected[fmt].content
        assert stored.sha256 == expected[fmt].sha256
        assert stored.size_bytes == len(stored.content)

    document = json.loads(files["json"].content)
    assert files["json"].content == canonical_json(document)
    snap = document["report"]
    assert snap == report.snapshot
    origin = f"http://lab.test:{scan_env.site.port}"

    instances = {
        (issue["rule"]["id"], i["subject_key"], i["discriminator"])
        for issue in snap["issues"]
        for i in issue["instances"]
    }
    assert instances == {
        (f.rule_id, f.subject_key, f.discriminator) for f in findings_of(scan_env, golden)
    }
    assert len(instances) == 12
    assert ("SV-INF-002", f"GET {origin}/error", "") in instances
    assert document["derived"]["totals"] == {
        "findings": 12,
        "active_findings": 12,
        "false_positives": 0,
        "issues": 11,
        "open_requiring_verification": 4,
        "evidence_referenced": len(snap["evidence"]),
    }
    assert document["derived"]["highest_active_severity"] == "low"

    # Rule text and verified taxonomy titles are frozen into the snapshot.
    trn = next(i["rule"] for i in snap["issues"] if i["rule"]["id"] == "SV-TRN-001")
    assert trn["owasp_top10"] == [{"id": "A04:2025", "title": "Cryptographic Failures"}]
    assert trn["cwe"][0]["id"] == 319 and trn["cwe"][0]["title"]
    assert trn["wstg"][0]["id"] == "WSTG-CRYP-03" and trn["wstg"][0]["url"].startswith("https://")
    assert snap["methodology"]["rules_available"] is True
    assert len(snap["methodology"]["rules"]) == 14

    # Evidence: referenced records only, hashes labelled, excerpts only for
    # body-content issues, and never a secret.
    cited = {e for issue in snap["issues"] for i in issue["instances"] for e in i["evidence_ids"]}
    assert {e["id"] for e in snap["evidence"]} == cited
    excerpt_rules = {"SV-INF-002", "SV-INF-003"}
    excerpt_evidence = {
        e
        for issue in snap["issues"]
        if issue["rule"]["id"] in excerpt_rules
        for i in issue["instances"]
        for e in i["evidence_ids"]
    }
    for record in snap["evidence"]:
        assert record["body_sha256_label"] == "SHA-256 of the unredacted captured response bytes."
        assert (record["excerpt"] is not None) == (record["id"] in excerpt_evidence)
    error_page = next(e for e in snap["evidence"] if e["url"].endswith("/error"))
    assert "Traceback (most recent call last)" in error_page["excerpt"]

    html = files["html"].content.decode()
    assert "Golden lab assessment" in html and "SV-INF-002" in html
    everything = json.dumps(report.snapshot) + "".join(
        a.content.decode("utf-8", "replace") for a in files.values()
    )
    assert SESSION_SECRET not in everything
    assert CSRF_SECRET not in everything


def test_report_links_cite_exactly_the_snapshot(scan_env: ScanEnv, golden: uuid.UUID) -> None:
    report_id = request_report(scan_env, golden)
    snap = load(scan_env, report_id).snapshot
    with scan_env.factory() as s:
        findings = set(
            s.scalars(
                text("SELECT finding_id::text FROM report_findings WHERE report_id = :r"),
                {"r": report_id},
            )
        )
        evidence = set(
            s.scalars(
                text("SELECT evidence_id::text FROM report_evidence WHERE report_id = :r"),
                {"r": report_id},
            )
        )
    assert findings == {i["finding_id"] for issue in snap["issues"] for i in issue["instances"]}
    assert evidence == {e["id"] for e in snap["evidence"]}


# --- eligibility --------------------------------------------------------------------------


def test_report_eligibility_rules(
    scan_env: ScanEnv, golden: uuid.UUID, committed_api: TestClient
) -> None:
    api = committed_api
    assessment_id = assessment_of(scan_env, golden)
    url = f"/api/v1/assessments/{assessment_id}/reports"
    body = {"scan_id": str(golden), "title": "T", "prepared_by": "P", "formats": LOCAL_FORMATS}

    final = api.post(url, json={**body, "kind": "final"})
    assert final.status_code == 409
    assert final.json()["reason"] == "assessment_not_completed"
    assert api.post(url, json={**body, "formats": ["html"]}).status_code == 422
    assert api.post(url, json={**body, "formats": ["json", "json"]}).status_code == 422
    assert api.post(url, json={**body, "formats": ["json", "docx"]}).status_code == 422
    assert api.post(url, json={**body, "template": "sv-standard@9"}).status_code == 422
    assert api.post(url, json={**body, "classification": "top-secret"}).status_code == 422
    assert api.post(url, json={**body, "extra": 1}).status_code == 422
    assert api.post(url, json={**body, "scan_id": str(uuid.uuid4())}).status_code == 404
    assert api.post(f"/api/v1/assessments/{uuid.uuid4()}/reports", json=body).status_code == 404

    draft = api.post(url, json=body)  # assessment still in progress: a draft is allowed
    assert draft.status_code == 202
    assert draft.json()["status"] == "queued" and draft.json()["kind"] == "draft"

    complete_assessment(scan_env, assessment_id)
    assert api.post(url, json={**body, "kind": "final"}).status_code == 202


def test_reports_require_a_completed_and_analysed_scan(
    scan_env: ScanEnv, committed_api: TestClient
) -> None:
    golden_report_site(scan_env)
    _, assessment_id, scan_id = scan_env.queued_scan()
    url = f"/api/v1/assessments/{assessment_id}/reports"
    body = {"scan_id": str(scan_id), "title": "T", "prepared_by": "P", "formats": LOCAL_FORMATS}

    queued = committed_api.post(url, json=body)
    assert queued.status_code == 409 and queued.json()["reason"] == "scan_not_completed"

    worker = scan_env.worker(role=WorkerRole.SCANS)
    claimed = worker.claim()
    assert claimed is not None
    worker.execute(claimed)  # scan completed, analysis still queued
    pending = committed_api.post(url, json=body)
    assert pending.status_code == 409 and pending.json()["reason"] == "analysis_not_completed"

    assert worker.analyze_once()
    assert committed_api.post(url, json=body).status_code == 202


def test_a_scan_of_another_assessment_is_refused(scan_env: ScanEnv, golden: uuid.UUID) -> None:
    other_assessment = scan_env.started_assessment(scan_env.target())
    with scan_env.factory() as s:
        data = ReportCreate(scan_id=golden, title="T", prepared_by="P")
        with pytest.raises(NotFoundError, match="scan not found"):
            get_report_service(s, utc_now).create(other_assessment, data)


# --- snapshot semantics ------------------------------------------------------------------


def test_snapshot_is_frozen_when_the_report_is_requested(
    scan_env: ScanEnv, golden: uuid.UUID
) -> None:
    first = request_report(scan_env, golden)
    second = request_report(scan_env, golden)
    a, b = load(scan_env, first), load(scan_env, second)
    # Same data, same inputs: same content; different report identity.
    assert a.content_sha256 == b.content_sha256
    assert a.snapshot_sha256 != b.snapshot_sha256
    assert a.number != b.number

    finding = findings_of(scan_env, golden)[0]
    with scan_env.factory() as s:
        get_finding_service(s, utc_now).triage(
            finding.id, FindingStatus.FALSE_POSITIVE, "lab artefact", "Lead"
        )
    third = load(scan_env, request_report(scan_env, golden))
    assert third.content_sha256 != a.content_sha256

    def status_in(report: Report) -> str:
        return next(
            str(i["status"])
            for issue in report.snapshot["issues"]
            for i in issue["instances"]
            if i["finding_id"] == str(finding.id)
        )

    assert status_in(load(scan_env, first)) == "open"  # unchanged by later triage
    assert status_in(third) == "false_positive"
    assert any(e["kind"] == "finding_triaged" for e in third.snapshot["timeline"]["entries"])

    assert report_worker(scan_env).run_once()
    assert report_worker(scan_env).run_once()
    assert report_worker(scan_env).run_once()
    html = artifacts(scan_env, third.id)["html"].content.decode()
    fp_section = html.split('id="false-positives"')[1].split('id="evidence"')[0]
    assert "lab artefact" in fp_section


def test_a_report_request_waits_for_in_flight_triage(
    scan_env: ScanEnv, golden: uuid.UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The snapshot share-locks the run's findings while reading them, so it
    cannot interleave with a triage that holds a finding's row lock: it waits
    (here, until a short lock timeout) before reading anything further. It
    must block at that read, not later at the link insert (whose foreign-key
    check would also wait, but only after a possibly torn read)."""
    finding = findings_of(scan_env, golden)[0]
    assessment_id = assessment_of(scan_env, golden)
    data = ReportCreate(scan_id=golden, title="T", prepared_by="P", formats=["json"])

    def reached_links(*_: Any, **__: Any) -> None:
        raise AssertionError("the snapshot was read without waiting for the triage")

    with scan_env.factory() as holder:
        AnalysisRepository(holder).get_finding_for_update(finding.id)  # triage in progress
        with monkeypatch.context() as m, scan_env.factory() as s:
            m.setattr(ReportRepository, "add_links", reached_links)
            s.execute(text("SET LOCAL lock_timeout = '300ms'"))
            with pytest.raises(OperationalError, match="lock timeout"):
                get_report_service(s, utc_now).create(assessment_id, data)
        holder.rollback()
    with scan_env.factory() as s:
        assert get_report_service(s, utc_now).create(assessment_id, data).id


def test_report_cites_the_scans_authorization_not_the_targets_current_one(
    scan_env: ScanEnv, golden: uuid.UUID
) -> None:
    scan = scan_env.get_scan(golden)
    with scan_env.factory() as s:
        version = s.scalar(
            text("SELECT version FROM target_authorizations WHERE id = :a"),
            {"a": scan.authorization_id},
        )
    scan_env.reauthorize(scan.target_id, reference="LAB-REAUTH")
    snap = load(scan_env, request_report(scan_env, golden)).snapshot
    assert snap["engagement"]["authorization"]["id"] == str(scan.authorization_id)
    assert snap["engagement"]["authorization"]["version"] == version
    assert snap["engagement"]["authorization"]["reference"] == "LAB-SCAN"
    assert snap["scope"]["excluded_paths"] == ["/admin"]


# --- database guarantees ------------------------------------------------------------------


def _rejected(env: ScanEnv, sql: str, params: Mapping[str, Any], match: str) -> None:
    with env.factory() as s, pytest.raises((IntegrityError, DBAPIError), match=match):
        s.execute(text(sql), dict(params))
        s.flush()


@pytest.fixture
def completed_report(scan_env: ScanEnv, golden: uuid.UUID) -> uuid.UUID:
    report_id = request_report(scan_env, golden)
    assert report_worker(scan_env).run_once()
    assert load(scan_env, report_id).status is ReportStatus.COMPLETED
    return report_id


@pytest.mark.parametrize(
    ("sql", "match"),
    [
        ("UPDATE reports SET title = 'changed' WHERE id = :r", "immutable"),
        ("UPDATE reports SET snapshot = '{}'::jsonb WHERE id = :r", "immutable"),
        ("UPDATE reports SET status = 'failed', error_code = 'x' WHERE id = :r", "immutable"),
        ("DELETE FROM reports WHERE id = :r", "cannot be deleted"),
        ("UPDATE report_artifacts SET renderer = 'x' WHERE report_id = :r", "immutable"),
        ("DELETE FROM report_artifacts WHERE report_id = :r", "immutable"),
        ("DELETE FROM report_findings WHERE report_id = :r", "immutable"),
        ("DELETE FROM report_evidence WHERE report_id = :r", "immutable"),
        (
            "INSERT INTO report_artifacts (report_id, format, media_type, content, size_bytes, "
            "sha256, renderer) VALUES (:r, 'pdf', 'application/pdf', '\\x01'::bytea, 1, "
            "encode(sha256('\\x01'::bytea), 'hex'), 'x')",
            "generating report",
        ),
    ],
)
def test_completed_reports_are_immutable(
    scan_env: ScanEnv, completed_report: uuid.UUID, sql: str, match: str
) -> None:
    _rejected(scan_env, sql, {"r": completed_report}, match)


def test_report_content_is_frozen_while_queued(scan_env: ScanEnv, golden: uuid.UUID) -> None:
    report_id = request_report(scan_env, golden)
    for sql in (
        "UPDATE reports SET snapshot = '{}'::jsonb WHERE id = :r",
        "UPDATE reports SET kind = 'final' WHERE id = :r",
        "UPDATE reports SET content_sha256 = repeat('0', 64) WHERE id = :r",
    ):
        _rejected(scan_env, sql, {"r": report_id}, "immutable")
    # Status transitions are restricted too: queued cannot jump to completed.
    _rejected(
        scan_env,
        "UPDATE reports SET status = 'completed', finished_at = now(), claimed_by = 'w', "
        "claimed_at = now() WHERE id = :r",
        {"r": report_id},
        "transition",
    )


def test_a_report_cannot_complete_without_exactly_its_artifacts(
    scan_env: ScanEnv, golden: uuid.UUID
) -> None:
    report_id = request_report(scan_env, golden)
    with scan_env.factory() as s:
        s.execute(
            text(
                "UPDATE reports SET status = 'generating', claimed_by = 'w', claimed_at = now() "
                "WHERE id = :r"
            ),
            {"r": report_id},
        )
        s.commit()
    _rejected(
        scan_env,
        "UPDATE reports SET status = 'completed', finished_at = now() WHERE id = :r",
        {"r": report_id},
        "exactly its requested artifacts",
    )
    # An artifact in a format the report did not request is refused.
    _rejected(
        scan_env,
        "INSERT INTO report_artifacts (report_id, format, media_type, content, size_bytes, "
        "sha256, renderer) VALUES (:r, 'pdf', 'application/pdf', '\\x01'::bytea, 1, "
        "encode(sha256('\\x01'::bytea), 'hex'), 'x')",
        {"r": report_id},
        "requested format",
    )


@pytest.mark.parametrize(
    ("content", "size", "sha", "match"),
    [
        ("'\\x01'::bytea", 1, "repeat('0', 64)", "sha256_matches_content"),
        ("'\\x0102'::bytea", 1, "encode(sha256('\\x0102'::bytea), 'hex')", "size_matches_content"),
        (
            "decode(repeat('00', 26214401), 'hex')",
            26214401,
            "encode(sha256(decode(repeat('00', 26214401), 'hex')), 'hex')",
            "size_within_limit",
        ),
    ],
)
def test_artifact_integrity_and_size_constraints(
    scan_env: ScanEnv, golden: uuid.UUID, content: str, size: int, sha: str, match: str
) -> None:
    report_id = request_report(scan_env, golden)
    with scan_env.factory() as s:
        s.execute(
            text(
                "UPDATE reports SET status = 'generating', claimed_by = 'w', claimed_at = now() "
                "WHERE id = :r"
            ),
            {"r": report_id},
        )
        s.commit()
    # The SQL fragments are the parametrized test constants above.
    values = f"(:r, 'json', 'application/json', {content}, {size}, {sha}, 'x')"
    sql = (
        "INSERT INTO report_artifacts "  # noqa: S608
        "(report_id, format, media_type, content, size_bytes, sha256, renderer) VALUES " + values
    )
    _rejected(scan_env, sql, {"r": report_id}, match)


def test_report_links_cannot_cross_scans(scan_env: ScanEnv, golden: uuid.UUID) -> None:
    other_scan = scan_and_analyse(scan_env)
    report_id = request_report(scan_env, golden)
    other_finding = findings_of(scan_env, other_scan)[0]
    with scan_env.factory() as s:
        other_evidence = s.scalar(
            text("SELECT id FROM evidence WHERE scan_id = :s LIMIT 1"), {"s": other_scan}
        )
    for sql, params, match in [
        (
            "INSERT INTO report_findings VALUES (:r, :s, :f, 'open')",
            {"r": report_id, "s": golden, "f": other_finding.id},
            "fk_report_findings_finding",
        ),
        (
            "INSERT INTO report_findings VALUES (:r, :s, :f, 'open')",
            {"r": report_id, "s": other_scan, "f": other_finding.id},
            "fk_report_findings_report",
        ),
        (
            "INSERT INTO report_evidence VALUES (:r, :s, :e)",
            {"r": report_id, "s": golden, "e": other_evidence},
            "fk_report_evidence_evidence",
        ),
    ]:
        _rejected(scan_env, sql, params, match)


def test_cited_findings_and_evidence_cannot_be_deleted(
    scan_env: ScanEnv, golden: uuid.UUID
) -> None:
    report_id = request_report(scan_env, golden)
    with scan_env.factory() as s:
        finding_id = s.scalar(
            text("SELECT finding_id FROM report_findings WHERE report_id = :r LIMIT 1"),
            {"r": report_id},
        )
        evidence_id = s.scalar(
            text("SELECT evidence_id FROM report_evidence WHERE report_id = :r LIMIT 1"),
            {"r": report_id},
        )
    _rejected(scan_env, "DELETE FROM findings WHERE id = :f", {"f": finding_id}, "report_findings")
    # Cited evidence is also referenced by its finding; remove that link first
    # (in the same, rolled-back transaction) so only the report's link remains.
    with scan_env.factory() as s, pytest.raises(IntegrityError, match="report_evidence"):
        s.execute(text("DELETE FROM finding_evidence WHERE evidence_id = :e"), {"e": evidence_id})
        s.execute(text("DELETE FROM evidence WHERE id = :e"), {"e": evidence_id})


# --- worker ------------------------------------------------------------------------------


def test_worker_roles_are_separate(scan_env: ScanEnv, golden: uuid.UUID) -> None:
    report_id = request_report(scan_env, golden)
    _, _, scan_id = scan_env.queued_scan()
    scans_only = scan_env.worker("scans-only", role=WorkerRole.SCANS)
    reports_only = report_worker(scan_env)

    assert reports_only.run_once()  # renders the report...
    assert load(scan_env, report_id).status is ReportStatus.COMPLETED
    assert not reports_only.run_once()  # ...and never touches the queued scan
    assert scan_env.get_scan(scan_id).status.value == "queued"

    second = request_report(scan_env, golden)
    assert scans_only.run_once()  # runs the scan...
    assert scans_only.run_once()  # ...and its analysis
    assert not scans_only.run_once()  # ...but never the queued report
    assert load(scan_env, second).status is ReportStatus.QUEUED


@pytest.mark.parametrize("attempt", range(3))
def test_concurrent_report_workers_generate_each_report_once(
    scan_env: ScanEnv, golden: uuid.UUID, attempt: int
) -> None:
    report_ids = [request_report(scan_env, golden) for _ in range(2)]
    barrier = threading.Barrier(4)
    done: list[bool] = []
    lock = threading.Lock()

    def work(name: str) -> None:
        worker = report_worker(scan_env, name)
        barrier.wait()
        processed = worker.report_once()
        with lock:
            done.append(processed)

    threads = [threading.Thread(target=work, args=(f"r{attempt}-{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    while report_worker(scan_env).report_once():
        pass
    for report_id in report_ids:
        report = load(scan_env, report_id)
        assert report.status is ReportStatus.COMPLETED
        assert set(artifacts(scan_env, report_id)) == {"json", "html"}
    assert done.count(True) <= len(report_ids)


def test_a_locked_report_is_skipped(scan_env: ScanEnv, golden: uuid.UUID) -> None:
    report_id = request_report(scan_env, golden)
    with scan_env.factory() as holder:
        ReportRepository(holder).get_for_update(report_id)
        assert not report_worker(scan_env, "other").report_once()
        holder.rollback()
    assert report_worker(scan_env, "other").report_once()


def test_rendering_happens_without_a_database_session(scan_env: ScanEnv, golden: uuid.UUID) -> None:
    report_id = request_report(scan_env, golden)
    seen: dict[str, int] = {}

    def renderer(snapshot: Mapping[str, Any], formats: Iterable[str]) -> tuple[Artifact, ...]:
        with scan_env.factory() as s:
            seen["connections"] = int(
                s.scalar(
                    text(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                        "AND state = 'idle in transaction'"
                    )
                )
                or 0
            )
        return render_report(snapshot, formats)

    assert report_worker(scan_env, report_renderer=renderer).run_once()
    assert seen["connections"] == 0  # no transaction held open by the worker
    assert load(scan_env, report_id).status is ReportStatus.COMPLETED


def test_render_errors_fail_the_report_with_a_code_only(
    scan_env: ScanEnv, golden: uuid.UUID
) -> None:
    def leaky(snapshot: Mapping[str, Any], formats: Iterable[str]) -> tuple[Artifact, ...]:
        raise RuntimeError(f"boom {SESSION_SECRET}")

    def too_large(snapshot: Mapping[str, Any], formats: Iterable[str]) -> tuple[Artifact, ...]:
        raise ArtifactTooLarge("pdf")

    for renderer, code in ((leaky, "render_error"), (too_large, "artifact_too_large")):
        report_id = request_report(scan_env, golden)
        assert report_worker(scan_env, report_renderer=renderer).run_once()
        report = load(scan_env, report_id)
        assert report.status is ReportStatus.FAILED
        assert report.error_code == code
        assert artifacts(scan_env, report_id) == {}
        assert SESSION_SECRET not in json.dumps(
            {c.key: str(getattr(report, c.key)) for c in Report.__table__.columns}
        )
        assert not report_worker(scan_env).report_once()  # failed reports are not retried


def test_a_renderer_returning_the_wrong_formats_fails_the_report(
    scan_env: ScanEnv, golden: uuid.UUID
) -> None:
    def json_only(snapshot: Mapping[str, Any], formats: Iterable[str]) -> tuple[Artifact, ...]:
        return render_report(snapshot, ["json"])

    report_id = request_report(scan_env, golden)
    assert report_worker(scan_env, report_renderer=json_only).run_once()
    assert load(scan_env, report_id).error_code == "render_error"


def test_a_crashed_worker_leaves_the_report_for_the_reaper(
    scan_env: ScanEnv, golden: uuid.UUID
) -> None:
    class Crash(BaseException):
        """Stands in for the process dying while rendering."""

    def crash(snapshot: Mapping[str, Any], formats: Iterable[str]) -> tuple[Artifact, ...]:
        raise Crash

    report_id = request_report(scan_env, golden)
    crashing = report_worker(scan_env, "crashing", report_renderer=crash)
    claimed = crashing.claim_report(report_id)
    assert claimed is not None
    with pytest.raises(Crash):
        crashing.generate_report(claimed)
    assert load(scan_env, report_id).status is ReportStatus.GENERATING

    # A healthy report worker reaps it once it is stale (database clock).
    assert report_worker(scan_env, "fresh", report_stale_after=3600).reap_stale_reports() == 0
    with scan_env.factory() as s:
        s.execute(text("SELECT pg_sleep(0.05)"))
    assert report_worker(scan_env, "reaper", report_stale_after=0.01).reap_stale_reports() == 1
    report = load(scan_env, report_id)
    assert report.status is ReportStatus.FAILED and report.error_code == "worker_lost"

    # Late output from the lost worker is discarded.
    assert not crashing.finalize_report(
        claimed, render_report(claimed.snapshot, ["json", "html"]), None
    )
    assert artifacts(scan_env, report_id) == {}


# --- API ----------------------------------------------------------------------------------


def test_report_api(scan_env: ScanEnv, golden: uuid.UUID, committed_api: TestClient) -> None:
    api = committed_api
    assessment_id = assessment_of(scan_env, golden)
    created = api.post(
        f"/api/v1/assessments/{assessment_id}/reports",
        json={
            "scan_id": str(golden),
            "title": "<script>alert(1)</script> report",
            "prepared_by": "Tester",
            "formats": LOCAL_FORMATS,
            "executive_summary_note": "Scope agreed with the lab owner.",
        },
    )
    assert created.status_code == 202
    report = created.json()
    assert report["number"].startswith("SV-R-")
    assert "snapshot" not in report
    rid = report["id"]

    not_ready = api.get(f"/api/v1/reports/{rid}/artifacts/json")
    assert not_ready.status_code == 409
    assert api.get(f"/api/v1/reports/{rid}/preview").status_code == 409

    assert report_worker(scan_env).run_once()
    detail = api.get(f"/api/v1/reports/{rid}").json()
    assert detail["status"] == "completed"
    assert {a["format"] for a in detail["artifacts"]} == {"json", "html"}
    listed = api.get(f"/api/v1/assessments/{assessment_id}/reports").json()
    assert [r["id"] for r in listed] == [rid]
    assert {a["format"] for a in api.get(f"/api/v1/reports/{rid}/artifacts").json()} == {
        "json",
        "html",
    }

    download = api.get(f"/api/v1/reports/{rid}/artifacts/html")
    assert download.status_code == 200
    assert (
        download.headers["content-disposition"] == f'attachment; filename="{report["number"]}.html"'
    )
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in download.headers["content-security-policy"]
    stored = artifacts(scan_env, uuid.UUID(rid))["html"]
    assert download.content == stored.content
    assert download.headers["etag"] == f'"{stored.sha256}"'
    assert "<script>alert(1)</script>" not in download.text
    assert "&lt;script&gt;" in download.text

    preview = api.get(f"/api/v1/reports/{rid}/preview")
    assert preview.status_code == 200
    assert preview.headers["content-disposition"] == "inline"
    csp = preview.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "sandbox" in csp

    assert api.get(f"/api/v1/reports/{rid}/artifacts/pdf").status_code == 404  # not requested
    assert api.get(f"/api/v1/reports/{rid}/artifacts/exe").status_code == 422
    assert api.get(f"/api/v1/reports/{uuid.uuid4()}").status_code == 404
    assert api.get(f"/api/v1/assessments/{uuid.uuid4()}/reports").status_code == 404

    templates = api.get("/api/v1/report-templates").json()
    assert [(t["id"], t["version"]) for t in templates] == [("sv-standard", 1)]
    assert detail["template_hash"] == templates[0]["sha256"]


# --- PDF (needs Pango; required in CI and the Docker test run) ----------------------------


@pytest.mark.pdf
def test_golden_report_with_pdf(scan_env: ScanEnv, golden: uuid.UUID) -> None:
    import io

    from pypdf import PdfReader

    report_id = request_report(scan_env, golden, formats=["json", "html", "pdf"])
    assert report_worker(scan_env).run_once()
    report = load(scan_env, report_id)
    assert report.status is ReportStatus.COMPLETED, report.error_code
    pdf = artifacts(scan_env, report_id)["pdf"]
    assert pdf.content.startswith(b"%PDF-")
    assert (
        pdf.content == {a.format: a for a in render_report(report.snapshot, ["pdf"])}["pdf"].content
    )
    text_content = "\n".join(
        page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf.content)).pages
    )
    assert "SV-INF-002" in text_content
    assert SESSION_SECRET not in text_content and CSRF_SECRET not in text_content
