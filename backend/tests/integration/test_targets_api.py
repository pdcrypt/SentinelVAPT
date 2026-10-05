from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import (
    NOW,
    FrozenClock,
    authorization_payload,
    create_assessment,
    create_project,
    create_target,
    target_payload,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def project(api: TestClient) -> dict[str, Any]:
    return create_project(api)


def _targets_url(project: dict[str, Any]) -> str:
    return f"/api/v1/projects/{project['id']}/targets"


def test_create_target_normalizes_scope_and_records_acknowledgment(
    api: TestClient, project: dict[str, Any]
) -> None:
    target = create_target(
        api,
        project["id"],
        base_url="HTTP://Juice-Shop:3000/app/",
        in_scope_hosts=["Juice-Shop", "juice-shop"],
        in_scope_path_prefixes=["/app/"],
        excluded_paths=["/app/admin/"],
    )

    assert target["base_url"] == "http://juice-shop:3000/app/"
    assert target["in_scope_hosts"] == ["juice-shop"]
    assert target["allowed_ports"] == [3000]  # defaulted from base_url
    assert target["in_scope_path_prefixes"] == ["/app"]
    assert target["excluded_paths"] == ["/app/admin"]

    auth = target["authorization"]
    assert auth["status"] == "active"
    assert auth["reference"] == "LAB-001"
    # The acknowledging user is the authenticated one (Phase 9 M5).
    me = api.get("/api/v1/auth/me").json()["user"]
    assert auth["acknowledged_by"] == me["display_name"]
    assert auth["acknowledged_by_user_id"] == me["id"]
    # Set by the server from its clock, not by the client.
    assert auth["acknowledged_at"].startswith("2026-10-04T12:00:00")


@pytest.mark.parametrize(
    "auth_overrides",
    [
        {"acknowledge": False},
        {"acknowledge": None},
        {"authorized_by": "   "},
        {"reference": ""},
        {"valid_from": "2026-10-01T00:00:00"},  # naive datetime
        {"acknowledged_at": "2020-01-01T00:00:00Z"},  # server-controlled
    ],
)
def test_authorization_input_is_strict(
    api: TestClient, project: dict[str, Any], auth_overrides: dict[str, Any]
) -> None:
    payload = target_payload(authorization=authorization_payload(**auth_overrides))
    assert api.post(_targets_url(project), json=payload).status_code == 422


def test_authorization_is_required(api: TestClient, project: dict[str, Any]) -> None:
    payload = target_payload()
    del payload["authorization"]
    assert api.post(_targets_url(project), json=payload).status_code == 422


def test_rejects_authorization_window_already_ended(
    api: TestClient, project: dict[str, Any]
) -> None:
    payload = target_payload(
        authorization=authorization_payload(
            valid_from=(NOW - timedelta(days=10)).isoformat(),
            valid_until=(NOW - timedelta(days=1)).isoformat(),
        )
    )
    resp = api.post(_targets_url(project), json=payload)
    assert resp.status_code == 422
    assert resp.json()["field"] == "authorization"


@pytest.mark.parametrize(
    ("overrides", "field"),
    [
        ({"in_scope_hosts": ["*.juice-shop"]}, "in_scope_hosts"),
        ({"in_scope_hosts": ["10.0.0.0/8"]}, "in_scope_hosts"),
        ({"in_scope_hosts": ["example.com"], "base_url": "http://example.com/"}, "in_scope_hosts"),
        ({"base_url": "http://other-host/"}, "base_url"),
        ({"base_url": "http://user:pw@juice-shop:3000/"}, "base_url"),
        ({"base_url": "ftp://juice-shop/"}, "base_url"),
        ({"allowed_ports": [8080]}, "base_url"),
        ({"excluded_paths": ["/"]}, "base_url"),
        (
            {
                "environment": "authorized_external",
                "in_scope_hosts": ["169.254.169.254"],
                "base_url": "http://169.254.169.254/",
            },
            "in_scope_hosts",
        ),
    ],
)
def test_scope_violations_are_rejected(
    api: TestClient, project: dict[str, Any], overrides: dict[str, Any], field: str
) -> None:
    resp = api.post(_targets_url(project), json=target_payload(**overrides))
    assert resp.status_code == 422, resp.text
    assert resp.json()["code"] == "validation_error"
    assert resp.json()["field"] == field


def test_external_target_with_public_host(api: TestClient, project: dict[str, Any]) -> None:
    target = create_target(
        api,
        project["id"],
        environment="authorized_external",
        base_url="https://staging.example.com/",
        in_scope_hosts=["staging.example.com"],
    )
    assert target["allowed_ports"] == [443]


def test_target_name_unique_per_project(api: TestClient, project: dict[str, Any]) -> None:
    create_target(api, project["id"])
    assert api.post(_targets_url(project), json=target_payload()).status_code == 409

    other = create_project(api, "Other project")
    create_target(api, other["id"])  # same name, different project: fine


def test_create_target_in_missing_project_is_404(api: TestClient) -> None:
    url = "/api/v1/projects/00000000-0000-0000-0000-000000000000/targets"
    assert api.post(url, json=target_payload()).status_code == 404


def test_scope_change_requires_reacknowledgment(
    api: TestClient, project: dict[str, Any], clock: FrozenClock
) -> None:
    target = create_target(api, project["id"])
    url = f"/api/v1/targets/{target['id']}"

    resp = api.patch(url, json={"in_scope_hosts": ["juice-shop", "dvwa"]})
    assert resp.status_code == 422
    assert resp.json()["field"] == "authorization"

    clock.advance(timedelta(hours=1))
    resp = api.patch(
        url,
        json={
            "in_scope_hosts": ["juice-shop", "dvwa"],
            "authorization": authorization_payload(),
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["in_scope_hosts"] == ["juice-shop", "dvwa"]
    me = api.get("/api/v1/auth/me").json()["user"]
    assert body["authorization"]["acknowledged_by_user_id"] == me["id"]
    assert body["authorization"]["acknowledged_at"].startswith("2026-10-04T13:00:00")


def test_scope_update_is_validated_against_existing_values(
    api: TestClient, project: dict[str, Any]
) -> None:
    target = create_target(api, project["id"])
    # Dropping the base_url host from scope must fail even though base_url is unchanged.
    resp = api.patch(
        f"/api/v1/targets/{target['id']}",
        json={"in_scope_hosts": ["dvwa"], "authorization": authorization_payload()},
    )
    assert resp.status_code == 422
    assert resp.json()["field"] == "base_url"


def test_rename_does_not_require_reacknowledgment(api: TestClient, project: dict[str, Any]) -> None:
    target = create_target(api, project["id"])
    resp = api.patch(f"/api/v1/targets/{target['id']}", json={"name": "Renamed"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "Renamed"
    assert resp.json()["authorization"] == target["authorization"]


def test_authorization_status_follows_the_clock(
    api: TestClient, project: dict[str, Any], clock: FrozenClock
) -> None:
    target = create_target(
        api,
        project["id"],
        authorization=authorization_payload(
            valid_from=(NOW + timedelta(days=1)).isoformat(),
            valid_until=(NOW + timedelta(days=2)).isoformat(),
        ),
    )
    url = f"/api/v1/targets/{target['id']}"
    assert target["authorization"]["status"] == "pending"

    clock.advance(timedelta(days=1, hours=1))
    assert api.get(url).json()["authorization"]["status"] == "active"

    clock.advance(timedelta(days=1))
    assert api.get(url).json()["authorization"]["status"] == "expired"


def test_list_targets(api: TestClient, project: dict[str, Any]) -> None:
    a = create_target(api, project["id"], name="A")
    b = create_target(api, project["id"], name="B")
    listed = api.get(_targets_url(project)).json()
    assert {t["id"] for t in listed} == {a["id"], b["id"]}


def test_delete_target(api: TestClient, project: dict[str, Any]) -> None:
    target = create_target(api, project["id"])
    assert api.delete(f"/api/v1/targets/{target['id']}").status_code == 204
    assert api.get(f"/api/v1/targets/{target['id']}").status_code == 404


def test_cannot_delete_target_with_assessments(api: TestClient, project: dict[str, Any]) -> None:
    target = create_target(api, project["id"])
    create_assessment(api, target["id"])
    assert api.delete(f"/api/v1/targets/{target['id']}").status_code == 409
