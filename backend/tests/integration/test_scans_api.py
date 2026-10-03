"""Scan API: creation rules, cancellation, assessment interplay and reads."""

from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection

from app.repositories import ScanResultRepository
from app.services.scan_results import persist_discovery_result
from tests.integration.conftest import (
    FrozenClock,
    authorization_payload,
    create_assessment,
    create_project,
    create_target,
    open_session,
)
from tests.integration.test_scan_persistence import sample_result

pytestmark = pytest.mark.integration


@pytest.fixture
def project(api: TestClient) -> dict[str, Any]:
    return create_project(api)


@pytest.fixture
def target(api: TestClient, project: dict[str, Any]) -> dict[str, Any]:
    return create_target(api, project["id"])


def started(api: TestClient, target: dict[str, Any], name: str = "Baseline") -> dict[str, Any]:
    assessment = create_assessment(api, target["id"], name)
    resp = api.post(f"/api/v1/assessments/{assessment['id']}/start")
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    return body


def scan_url(assessment: dict[str, Any]) -> str:
    return f"/api/v1/assessments/{assessment['id']}/scans"


def create_scan(api: TestClient, assessment: dict[str, Any], **body: Any) -> dict[str, Any]:
    resp = api.post(scan_url(assessment), json=body or None)
    assert resp.status_code == 201, resp.text
    data: dict[str, Any] = resp.json()
    return data


# --- Creation -------------------------------------------------------------------------


def test_create_scan_queues_it(api: TestClient, target: dict[str, Any]) -> None:
    assessment = started(api, target)
    scan = create_scan(api, assessment)
    assert scan["status"] == "queued"
    assert scan["assessment_id"] == assessment["id"]
    assert scan["target_id"] == target["id"]
    assert scan["authorization_id"] == assessment["authorization_id"]
    assert scan["grant_snapshot"] is None  # only written when a worker claims it
    assert scan["cancel_requested"] is False
    assert scan["config"]["allow_untrusted_tls"] is False
    assert scan["config"]["limits"]["max_requests"] == 100  # scanner defaults, recorded
    assert scan["started_at"] is None and scan["finished_at"] is None


def test_allow_untrusted_tls_is_recorded(api: TestClient, target: dict[str, Any]) -> None:
    scan = create_scan(api, started(api, target), allow_untrusted_tls=True)
    assert scan["config"]["allow_untrusted_tls"] is True


@pytest.mark.parametrize(
    "body",
    [
        {"allow_untrusted_tls": 1},
        {"allow_untrusted_tls": "true"},
        {"limits": {"max_requests": 100000}},  # no limit overrides
        {"max_requests_per_second": 50},
        {"status": "running"},
        {"grant_snapshot": {}},
    ],
)
def test_scan_request_body_is_strict(
    api: TestClient, target: dict[str, Any], body: dict[str, Any]
) -> None:
    assert api.post(scan_url(started(api, target)), json=body).status_code == 422


def _refused(api: TestClient, assessment: dict[str, Any], reason: str) -> None:
    resp = api.post(scan_url(assessment))
    assert resp.status_code == 409, resp.text
    assert resp.json()["code"] == "scan_not_allowed"
    assert resp.json()["reason"] == reason


@pytest.mark.parametrize("action", [None, "/start/complete", "/cancel"])
def test_assessment_must_be_in_progress(
    api: TestClient, target: dict[str, Any], action: str | None
) -> None:
    assessment = create_assessment(api, target["id"])
    for step in (action or "").split("/")[1:]:
        if step == "start":
            api.post(f"/api/v1/assessments/{assessment['id']}/start")
        else:
            api.post(f"/api/v1/assessments/{assessment['id']}/{step}")
    _refused(api, assessment, "assessment_not_in_progress")


def test_superseded_authorization_is_refused(api: TestClient, target: dict[str, Any]) -> None:
    assessment = started(api, target)
    resp = api.patch(
        f"/api/v1/targets/{target['id']}",
        json={"authorization": authorization_payload(reference="RENEWED")},
    )
    assert resp.status_code == 200
    _refused(api, assessment, "authorization_superseded")


def test_expired_authorization_is_refused(
    api: TestClient, target: dict[str, Any], clock: FrozenClock
) -> None:
    assessment = started(api, target)
    clock.advance(timedelta(days=31))
    _refused(api, assessment, "authorization_not_active")


def test_external_targets_cannot_be_scanned(api: TestClient, project: dict[str, Any]) -> None:
    external = create_target(
        api,
        project["id"],
        name="External",
        environment="authorized_external",
        base_url="https://staging.example.com/",
        in_scope_hosts=["staging.example.com"],
    )
    _refused(api, started(api, external), "environment_not_supported")


def test_scanner_rules_are_applied_at_creation(api: TestClient, project: dict[str, Any]) -> None:
    """The backend accepts %61 in a configured path, but the scanner decodes it
    to an excluded path: the scan is refused up front, not at claim time."""
    tricky = create_target(
        api,
        project["id"],
        name="Tricky",
        base_url="http://juice-shop:3000/%61dmin/",
        excluded_paths=["/admin"],
    )
    _refused(api, started(api, tricky), "grant_invalid_scope")


def test_only_one_active_scan_per_assessment(api: TestClient, target: dict[str, Any]) -> None:
    assessment = started(api, target)
    create_scan(api, assessment)
    _refused(api, assessment, "active_scan_exists")


def test_missing_assessment_is_404(api: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert api.post(f"/api/v1/assessments/{missing}/scans").status_code == 404
    assert api.get(f"/api/v1/assessments/{missing}/scans").status_code == 404


# --- Cancellation ---------------------------------------------------------------------


def test_cancel_a_queued_scan(api: TestClient, target: dict[str, Any]) -> None:
    assessment = started(api, target)
    scan = create_scan(api, assessment)
    resp = api.post(f"/api/v1/scans/{scan['id']}/cancel")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "cancelled"
    assert body["cancel_reason"] == "user_request"
    assert body["finished_at"] is not None

    again = api.post(f"/api/v1/scans/{scan['id']}/cancel")
    assert again.status_code == 409
    assert again.json()["code"] == "invalid_state_transition"
    # A new scan can be requested once none is active.
    create_scan(api, assessment)


def test_cancel_missing_scan_is_404(api: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert api.post(f"/api/v1/scans/{missing}/cancel").status_code == 404
    assert api.get(f"/api/v1/scans/{missing}").status_code == 404


# --- Assessment interplay -------------------------------------------------------------


def test_assessment_cancel_cancels_its_queued_scan(api: TestClient, target: dict[str, Any]) -> None:
    assessment = started(api, target)
    scan = create_scan(api, assessment)
    assert api.post(f"/api/v1/assessments/{assessment['id']}/cancel").status_code == 200
    after = api.get(f"/api/v1/scans/{scan['id']}").json()
    assert after["status"] == "cancelled"
    assert after["cancel_reason"] == "assessment_cancelled"


def test_assessment_complete_waits_for_active_scans(
    api: TestClient, target: dict[str, Any]
) -> None:
    assessment = started(api, target)
    scan = create_scan(api, assessment)
    resp = api.post(f"/api/v1/assessments/{assessment['id']}/complete")
    assert resp.status_code == 409
    api.post(f"/api/v1/scans/{scan['id']}/cancel")
    assert api.post(f"/api/v1/assessments/{assessment['id']}/complete").status_code == 200


def test_assessments_with_scans_cannot_be_deleted(api: TestClient, target: dict[str, Any]) -> None:
    assessment = started(api, target)
    create_scan(api, assessment)
    api.post(f"/api/v1/assessments/{assessment['id']}/cancel")
    resp = api.delete(f"/api/v1/assessments/{assessment['id']}")
    assert resp.status_code == 409
    assert "scans" in resp.json()["detail"]


# --- Reads ----------------------------------------------------------------------------


def test_list_and_get_scans(api: TestClient, target: dict[str, Any]) -> None:
    assessment = started(api, target)
    first = create_scan(api, assessment)
    api.post(f"/api/v1/scans/{first['id']}/cancel")
    second = create_scan(api, assessment)
    listed = api.get(scan_url(assessment)).json()
    assert {s["id"] for s in listed} == {first["id"], second["id"]}
    assert api.get(f"/api/v1/scans/{second['id']}").json()["id"] == second["id"]
    assert len(api.get(scan_url(assessment), params={"limit": 1}).json()) == 1


def test_result_endpoints(
    api: TestClient, target: dict[str, Any], db_connection: Connection
) -> None:
    scan = create_scan(api, started(api, target))
    with open_session(db_connection) as session:
        persist_discovery_result(ScanResultRepository(session), scan["id"], sample_result())
        session.commit()
    base = f"/api/v1/scans/{scan['id']}"

    logs = api.get(f"{base}/logs").json()
    assert [entry["sequence"] for entry in logs] == list(range(1, len(logs) + 1))

    [asset] = api.get(f"{base}/assets").json()
    assert (asset["host"], asset["port"], asset["ip_addresses"]) == (
        "lab.test",
        8080,
        ["127.0.0.1"],
    )

    endpoints = api.get(f"{base}/endpoints").json()
    home = next(
        e for e in endpoints if e["url"] == "http://lab.test:8080/" and e["method"] == "GET"
    )
    assert home["status_code"] == 200
    assert home["cookies"] == [
        {
            "name": "SESSIONID",
            "secure": False,
            "http_only": True,
            "same_site": "Lax",
            "domain": None,
            "path": "/",
            "has_expiry": False,
        }
    ]
    skipped = api.get(f"{base}/endpoints", params={"fetched": "false"}).json()
    assert skipped and all(not e["fetched"] for e in skipped)
    assert [
        e["method"] for e in api.get(f"{base}/endpoints", params={"method": "options"}).json()
    ] == ["OPTIONS"]
    by_reason = api.get(f"{base}/endpoints", params={"skip_reason": "risky_path"}).json()
    assert [e["url"] for e in by_reason] == ["http://lab.test:8080/logout"]

    evidence = api.get(f"{base}/evidence").json()
    assert evidence and all(e["endpoint_id"] for e in evidence)
    single = api.get(f"/api/v1/evidence/{evidence[0]['id']}").json()
    assert single["id"] == evidence[0]["id"]
    missing = "00000000-0000-0000-0000-000000000000"
    assert api.get(f"/api/v1/evidence/{missing}").status_code == 404
    for path in ("logs", "assets", "endpoints", "evidence"):
        assert api.get(f"/api/v1/scans/{missing}/{path}").status_code == 404


def test_scans_have_no_write_endpoints_beyond_create_and_cancel(api: TestClient) -> None:
    paths = api.get("/openapi.json").json()["paths"]
    scan_ops = {
        (method.upper(), path)
        for path, ops in paths.items()
        if "/scans" in path or "/evidence" in path
        for method in ops
    }
    writes = {(m, p) for m, p in scan_ops if m != "GET"}
    assert writes == {
        ("POST", "/api/v1/assessments/{assessment_id}/scans"),
        ("POST", "/api/v1/scans/{scan_id}/cancel"),
    }
