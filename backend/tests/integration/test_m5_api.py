"""Phase 9 M5 at the API level, without the worker pipeline: scan requests and
triage record the authenticated user. Findings are inserted directly, so
these tests depend on nothing but the request path they check."""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models import User
from tests.integration.conftest import create_assessment, create_project, create_target
from tests.integration.test_analysis_constraints import INSERT_FINDING, _finding_params, ctx

pytestmark = pytest.mark.integration

__all__ = ["ctx"]


def test_scan_request_records_the_requester(api: TestClient, api_user: User) -> None:
    project = create_project(api)
    target = create_target(api, project["id"])
    assessment = create_assessment(api, target["id"])
    assert assessment["created_by_user_id"] == str(api_user.id)
    assert api.post(f"/api/v1/assessments/{assessment['id']}/start").status_code == 200
    scan = api.post(f"/api/v1/assessments/{assessment['id']}/scans", json={})
    assert scan.status_code == 201, scan.text
    assert scan.json()["requested_by_user_id"] == str(api_user.id)
    assert target["authorization"]["acknowledged_by_user_id"] == str(api_user.id)


def test_triage_records_the_user_id(
    api: TestClient, api_user: User, db_session: Session, ctx: dict[str, Any]
) -> None:
    db_session.execute(
        text(
            "INSERT INTO rule_versions (rule_id, version, metadata_hash, metadata) "
            "VALUES ('SV-TST-005', 1, 'h5', '{\"title\": \"M5 rule\"}')"
        )
    )
    params = _finding_params(ctx, rule="SV-TST-005")
    db_session.execute(text(INSERT_FINDING), params)
    db_session.commit()
    resp = api.post(f"/api/v1/findings/{params['id']}/triage", json={"status": "confirmed"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["status_changed_by_user_id"] == str(api_user.id)
    history = api.get(f"/api/v1/findings/{params['id']}/history").json()
    assert [h["changed_by_user_id"] for h in history] == [str(api_user.id)]
