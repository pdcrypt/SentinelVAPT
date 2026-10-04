"""The database keeps findings consistent even if services are bypassed
(ADR 0009): same-scan references only, immutable rule versions, rule-origin
findings only, and reasons for dismissive triage states."""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from tests.integration.conftest import create_assessment, create_project, create_target

pytestmark = pytest.mark.integration

RULE = "SV-TST-001"


def _scan(db: Session, assessment: dict[str, Any]) -> uuid.UUID:
    scan_id = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO scans (id, assessment_id, target_id, authorization_id, status, "
            "finished_at, config) VALUES (:id, :a, :t, :z, 'cancelled', now(), '{}')"
        ),
        {
            "id": scan_id,
            "a": assessment["id"],
            "t": assessment["target_id"],
            "z": assessment["authorization_id"],
        },
    )
    return scan_id


def _evidence(db: Session, scan_id: uuid.UUID) -> uuid.UUID:
    evidence_id = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO evidence (id, scan_id, scanner_evidence_id, method, url, "
            "request_headers, status_code, response_headers, body_excerpt, body_sha256, "
            "body_bytes_captured, truncated, peer, redactions) VALUES (:id, :s, "
            "gen_random_uuid(), 'GET', 'http://lab.test/', '[]', 200, '[]', '', '', 0, false, "
            "'127.0.0.1', '[]')"
        ),
        {"id": evidence_id, "s": scan_id},
    )
    return evidence_id


def _run(db: Session, scan_id: uuid.UUID) -> uuid.UUID:
    run_id = uuid.uuid4()
    db.execute(
        text("INSERT INTO analysis_runs (id, scan_id, ruleset_version) VALUES (:id, :s, 'rs-x')"),
        {"id": run_id, "s": scan_id},
    )
    return run_id


INSERT_FINDING = (
    "INSERT INTO findings (id, scan_id, assessment_id, target_id, analysis_run_id, rule_id, "
    "rule_version, origin, category, severity, confidence, detection_type, subject_type, "
    "subject_key, fingerprint, details, affected_count, status, status_reason) VALUES "
    "(:id, :scan, :a, :t, :run, :rule, 1, :origin, 'headers', :severity, 'high', "
    "'automated_detection', 'origin', 'http://lab.test:80', :fp, '{}', 1, :status, :reason)"
)


@pytest.fixture
def ctx(api: TestClient, db_session: Session) -> dict[str, Any]:
    project = create_project(api)
    target = create_target(api, project["id"])
    other_target = create_target(api, project["id"], name="Other")
    assessment = create_assessment(api, target["id"])
    other_assessment = create_assessment(api, other_target["id"])
    scan = _scan(db_session, assessment)
    other_scan = _scan(db_session, assessment)
    db_session.execute(
        text(
            "INSERT INTO rule_versions (rule_id, version, metadata_hash, metadata) "
            "VALUES (:r, 1, 'h', '{}')"
        ),
        {"r": RULE},
    )
    return {
        "assessment": assessment,
        "other_assessment": other_assessment,
        "scan": scan,
        "other_scan": other_scan,
        "run": _run(db_session, scan),
        "evidence": _evidence(db_session, scan),
        "other_evidence": _evidence(db_session, other_scan),
    }


def _finding_params(ctx: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    params = {
        "id": uuid.uuid4(),
        "scan": ctx["scan"],
        "a": ctx["assessment"]["id"],
        "t": ctx["assessment"]["target_id"],
        "run": ctx["run"],
        "rule": RULE,
        "origin": "rule",
        "severity": "low",
        "fp": uuid.uuid4().hex + uuid.uuid4().hex,
        "status": "open",
        "reason": None,
    }
    params.update(overrides)
    return params


def _rejected(db: Session, sql: str, params: dict[str, Any], match: str) -> None:
    with pytest.raises(IntegrityError, match=match), db.begin_nested():
        db.execute(text(sql), params)


def test_valid_finding_and_evidence_link_are_accepted(
    db_session: Session, ctx: dict[str, Any]
) -> None:
    params = _finding_params(ctx)
    db_session.execute(text(INSERT_FINDING), params)
    db_session.execute(
        text("INSERT INTO finding_evidence VALUES (:f, :e, :s)"),
        {"f": params["id"], "e": ctx["evidence"], "s": ctx["scan"]},
    )


def test_finding_must_match_its_scans_assessment_and_target(
    db_session: Session, ctx: dict[str, Any]
) -> None:
    other = ctx["other_assessment"]
    _rejected(
        db_session,
        INSERT_FINDING,
        _finding_params(ctx, a=other["id"], t=other["target_id"]),
        "fk_findings_scan",
    )


def test_finding_must_reference_a_recorded_rule_version(
    db_session: Session, ctx: dict[str, Any]
) -> None:
    _rejected(
        db_session, INSERT_FINDING, _finding_params(ctx, rule="SV-TST-999"), "fk_findings_rule"
    )


def test_evidence_links_cannot_cross_scans(db_session: Session, ctx: dict[str, Any]) -> None:
    params = _finding_params(ctx)
    db_session.execute(text(INSERT_FINDING), params)
    link = "INSERT INTO finding_evidence VALUES (:f, :e, :s)"
    # Evidence of another scan, claimed under this finding's scan.
    _rejected(
        db_session,
        link,
        {"f": params["id"], "e": ctx["other_evidence"], "s": ctx["scan"]},
        "fk_finding_evidence_evidence",
    )
    # Evidence of another scan, claimed under that scan: the finding does not match.
    _rejected(
        db_session,
        link,
        {"f": params["id"], "e": ctx["other_evidence"], "s": ctx["other_scan"]},
        "fk_finding_evidence_finding",
    )


def test_fingerprints_are_unique_per_scan(db_session: Session, ctx: dict[str, Any]) -> None:
    params = _finding_params(ctx)
    db_session.execute(text(INSERT_FINDING), params)
    _rejected(
        db_session,
        INSERT_FINDING,
        _finding_params(ctx, fp=params["fp"]),
        "uq_findings_scan_id_fingerprint",
    )


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"origin": "manual"}, "origin_rule_only"),
        ({"severity": "catastrophic"}, "severity_values"),
        ({"status": "fixed"}, "finding_status"),
        ({"status": "false_positive"}, "reason_required"),
        ({"status": "accepted_risk", "reason": "   "}, "reason_required"),
    ],
)
def test_finding_check_constraints(
    db_session: Session, ctx: dict[str, Any], overrides: dict[str, Any], constraint: str
) -> None:
    _rejected(db_session, INSERT_FINDING, _finding_params(ctx, **overrides), constraint)


def test_one_run_per_scan_and_ruleset(db_session: Session, ctx: dict[str, Any]) -> None:
    _rejected(
        db_session,
        "INSERT INTO analysis_runs (id, scan_id, ruleset_version) "
        "VALUES (gen_random_uuid(), :s, 'rs-x')",
        {"s": ctx["scan"]},
        "uq_analysis_runs_scan_id_ruleset_version",
    )
    _rejected(
        db_session,
        "UPDATE analysis_runs SET status = 'completed' WHERE id = :r",
        {"r": ctx["run"]},
        "finished_iff_terminal",
    )


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE rule_versions SET metadata_hash = 'other' WHERE rule_id = :r",
        "DELETE FROM rule_versions WHERE rule_id = :r",
    ],
)
def test_rule_versions_are_immutable(db_session: Session, ctx: dict[str, Any], sql: str) -> None:
    _rejected(db_session, sql, {"r": RULE}, "rule versions are immutable")


def test_scans_with_findings_cannot_be_deleted(db_session: Session, ctx: dict[str, Any]) -> None:
    db_session.execute(text(INSERT_FINDING), _finding_params(ctx))
    _rejected(
        db_session, "DELETE FROM scans WHERE id = :s", {"s": ctx["scan"]}, "analysis_runs|findings"
    )
