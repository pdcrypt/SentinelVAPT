"""The database rejects inconsistent scans and results even if services are
bypassed."""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from tests.integration.conftest import create_assessment, create_project, create_target

pytestmark = pytest.mark.integration


@pytest.fixture
def ctx(api: TestClient, db_session: Session) -> dict[str, Any]:
    project = create_project(api)
    target = create_target(api, project["id"])
    other = create_target(api, project["id"], name="Other")
    assessment = create_assessment(api, target["id"])
    api.post(f"/api/v1/assessments/{assessment['id']}/start")
    scan = api.post(f"/api/v1/assessments/{assessment['id']}/scans").json()
    return {"target": target, "other": other, "assessment": assessment, "scan": scan}


def _rejected(db_session: Session, sql: str, params: dict[str, Any], match: str) -> None:
    with pytest.raises(IntegrityError, match=match), db_session.begin_nested():
        db_session.execute(text(sql), params)


INSERT_SCAN = (
    "INSERT INTO scans (id, assessment_id, target_id, authorization_id, status, started_at, "
    "finished_at, claimed_by, config, requested_by_user_id) VALUES (gen_random_uuid(), :a, "
    ":t, :z, :status, :started, :finished, :worker, '{}', "
    "(SELECT created_by_user_id FROM assessments WHERE id = :a))"
)


def _scan_params(ctx: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    params = {
        "a": ctx["assessment"]["id"],
        "t": ctx["target"]["id"],
        "z": ctx["assessment"]["authorization_id"],
        "status": "cancelled",
        "started": None,
        "finished": "2026-10-04T12:00:00Z",
        "worker": None,
    }
    params.update(overrides)
    return params


def test_scan_must_use_its_assessments_target_and_authorization(
    db_session: Session, ctx: dict[str, Any]
) -> None:
    _rejected(
        db_session, INSERT_SCAN, _scan_params(ctx, t=ctx["other"]["id"]), "fk_scans_assessment"
    )
    _rejected(
        db_session,
        INSERT_SCAN,
        _scan_params(ctx, z=ctx["other"]["authorization"]["id"]),
        "fk_scans_assessment",
    )


def test_only_one_active_scan_per_assessment(db_session: Session, ctx: dict[str, Any]) -> None:
    _rejected(
        db_session,
        INSERT_SCAN,
        _scan_params(ctx, status="queued", finished=None),
        "uq_scans_one_active_per_assessment",
    )
    # Terminal scans do not count.
    db_session.execute(text(INSERT_SCAN), _scan_params(ctx))


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"status": "running", "finished": None, "worker": "w"}, "running_requires_started"),
        ({"status": "completed", "finished": "2026-10-04T12:00:00Z"}, "running_requires_started"),
        ({"status": "failed", "finished": None}, "finished_iff_terminal"),
        (
            {"status": "running", "started": "2026-10-04T12:00:00Z", "finished": None},
            "running_requires_worker",
        ),
        ({"status": "exploded", "finished": None}, "scan_status"),
    ],
)
def test_scan_state_checks(
    db_session: Session, ctx: dict[str, Any], overrides: dict[str, Any], constraint: str
) -> None:
    # Make room under the one-active-scan rule first.
    db_session.execute(
        text("UPDATE scans SET status = 'cancelled', finished_at = now() WHERE id = :s"),
        {"s": ctx["scan"]["id"]},
    )
    _rejected(db_session, INSERT_SCAN, _scan_params(ctx, **overrides), constraint)


def test_results_cannot_point_into_another_scan(db_session: Session, ctx: dict[str, Any]) -> None:
    scan_id = ctx["scan"]["id"]
    db_session.execute(
        text("UPDATE scans SET status = 'cancelled', finished_at = now() WHERE id = :s"),
        {"s": scan_id},
    )
    other_scan = uuid.uuid4()
    db_session.execute(
        text(INSERT_SCAN.replace("gen_random_uuid()", ":id")),
        {**_scan_params(ctx), "id": other_scan},
    )
    asset = uuid.uuid4()
    db_session.execute(
        text(
            "INSERT INTO assets (id, scan_id, scheme, host, port, ip_addresses) "
            "VALUES (:id, :s, 'http', 'lab.test', 80, '{}')"
        ),
        {"id": asset, "s": other_scan},
    )
    _rejected(
        db_session,
        "INSERT INTO endpoints (id, scan_id, asset_id, fingerprint, method, url, source, fetched, "
        "query_param_names, tech_hints) VALUES (gen_random_uuid(), :s, :asset, 'f', 'GET', "
        "'http://lab.test/', 'link', false, '{}', '[]')",
        {"s": scan_id, "asset": asset},
        "fk_endpoints_asset",
    )
