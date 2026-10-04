"""Append-only authorization history and target update rules."""

from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.repositories.target import TargetRepository
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


@pytest.fixture
def target(api: TestClient, project: dict[str, Any]) -> dict[str, Any]:
    return create_target(api, project["id"])


def _history(api: TestClient, target: dict[str, Any]) -> list[dict[str, Any]]:
    resp = api.get(f"/api/v1/targets/{target['id']}/authorizations")
    assert resp.status_code == 200, resp.text
    body: list[dict[str, Any]] = resp.json()
    return body


def _patch(api: TestClient, target: dict[str, Any], body: dict[str, Any]) -> Any:
    return api.patch(f"/api/v1/targets/{target['id']}", json=body)


def _without_live_fields(record: dict[str, Any]) -> dict[str, Any]:
    # is_current and status are computed at read time; everything else is stored.
    return {k: v for k, v in record.items() if k not in {"is_current", "status"}}


# --- Initial authorization --------------------------------------------------------


def test_initial_authorization_record(api: TestClient, target: dict[str, Any]) -> None:
    [record] = _history(api, target)
    assert record["version"] == 1
    assert record["is_current"] is True
    assert record["status"] == "active"
    assert record["id"] == target["authorization"]["id"]
    # The record holds exactly the scope that was acknowledged.
    for field in ("base_url", "environment", "in_scope_hosts", "allowed_ports"):
        assert record[field] == target[field]
    assert record["acknowledged_at"].startswith("2026-10-04T12:00:00")


# --- Re-authorization and scope changes append records -----------------------------


def test_reauthorization_appends_and_preserves_previous_record(
    api: TestClient, target: dict[str, Any], clock: FrozenClock
) -> None:
    [v1_before] = _history(api, target)
    clock.advance(timedelta(hours=1))

    resp = _patch(api, target, {"authorization": authorization_payload(reference="LAB-002")})
    assert resp.status_code == 200, resp.text
    assert resp.json()["authorization"]["version"] == 2
    assert resp.json()["authorization"]["reference"] == "LAB-002"

    v2, v1_after = _history(api, target)
    assert (v2["version"], v2["is_current"]) == (2, True)
    assert v1_after["is_current"] is False
    assert _without_live_fields(v1_after) == _without_live_fields(v1_before)
    assert v2["acknowledged_at"].startswith("2026-10-04T13:00:00")


def test_scope_change_creates_record_with_new_scope_and_keeps_old_scope(
    api: TestClient, target: dict[str, Any]
) -> None:
    resp = _patch(
        api,
        target,
        {"in_scope_hosts": ["juice-shop", "dvwa"], "authorization": authorization_payload()},
    )
    assert resp.status_code == 200, resp.text

    v2, v1 = _history(api, target)
    assert v2["in_scope_hosts"] == ["juice-shop", "dvwa"]
    assert v1["in_scope_hosts"] == ["juice-shop"]
    assert resp.json()["in_scope_hosts"] == ["juice-shop", "dvwa"]


def test_rename_does_not_create_a_record(api: TestClient, target: dict[str, Any]) -> None:
    resp = _patch(api, target, {"name": "Renamed"})
    assert resp.status_code == 200
    assert len(_history(api, target)) == 1


def test_rejected_update_creates_no_record(api: TestClient, target: dict[str, Any]) -> None:
    resp = _patch(
        api, target, {"in_scope_hosts": ["dvwa"], "authorization": authorization_payload()}
    )
    assert resp.status_code == 422
    assert len(_history(api, target)) == 1


def test_assessment_records_the_authorization_it_was_planned_under(
    api: TestClient, target: dict[str, Any]
) -> None:
    assessment = create_assessment(api, target["id"])
    v1_id = target["authorization"]["id"]
    assert assessment["authorization_id"] == v1_id

    _patch(
        api,
        target,
        {"in_scope_hosts": ["juice-shop", "dvwa"], "authorization": authorization_payload()},
    )
    # The assessment still points at v1, whose scope is preserved.
    assert api.get(f"/api/v1/assessments/{assessment['id']}").json()["authorization_id"] == v1_id
    v1 = next(r for r in _history(api, target) if r["id"] == v1_id)
    assert v1["in_scope_hosts"] == ["juice-shop"]


# --- Expiry and re-authorizing an expired target -----------------------------------


def test_reauthorizing_an_expired_target(
    api: TestClient, target: dict[str, Any], clock: FrozenClock
) -> None:
    old_plan = create_assessment(api, target["id"], "planned under v1")
    clock.advance(timedelta(days=31))  # v1 window has ended

    assert _history(api, target)[0]["status"] == "expired"
    assert api.get(f"/api/v1/targets/{target['id']}").json()["authorization"]["status"] == "expired"
    resp = api.post(f"/api/v1/targets/{target['id']}/assessments", json={"name": "late"})
    assert resp.status_code == 409

    renewed = _patch(
        api,
        target,
        {
            "authorization": authorization_payload(
                valid_from=clock.now.isoformat(),
                valid_until=(clock.now + timedelta(days=7)).isoformat(),
            )
        },
    )
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["authorization"]["status"] == "active"

    v2, v1 = _history(api, target)
    assert (v1["status"], v2["status"]) == ("expired", "active")

    # An assessment planned under the superseded record cannot start ...
    resp = api.post(f"/api/v1/assessments/{old_plan['id']}/start")
    assert resp.status_code == 409
    assert "re-authorized" in resp.json()["detail"]
    # ... but a new one, planned under the current record, can.
    new_plan = create_assessment(api, target["id"], "planned under v2")
    assert new_plan["authorization_id"] == v2["id"]
    assert api.post(f"/api/v1/assessments/{new_plan['id']}/start").status_code == 200


# --- Environment switching re-validates scope --------------------------------------


def test_switching_lab_to_external_allows_public_hosts(
    api: TestClient, target: dict[str, Any]
) -> None:
    public = {
        "base_url": "https://staging.example.com/",
        "in_scope_hosts": ["staging.example.com"],
        "allowed_ports": [443],
        "authorization": authorization_payload(),
    }
    assert _patch(api, target, public).status_code == 422  # still local_lab

    resp = _patch(api, target, {**public, "environment": "authorized_external"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["environment"] == "authorized_external"
    assert _history(api, target)[0]["environment"] == "authorized_external"


def test_switching_external_to_lab_revalidates_existing_hosts(
    api: TestClient, project: dict[str, Any]
) -> None:
    external = create_target(
        api,
        project["id"],
        name="External",
        environment="authorized_external",
        base_url="https://staging.example.com/",
        in_scope_hosts=["staging.example.com"],
    )
    resp = _patch(
        api, external, {"environment": "local_lab", "authorization": authorization_payload()}
    )
    assert resp.status_code == 422
    assert resp.json()["field"] == "in_scope_hosts"
    assert len(_history(api, external)) == 1


# --- Strict inputs -------------------------------------------------------------------


def test_patch_with_null_authorization_is_rejected(api: TestClient, target: dict[str, Any]) -> None:
    assert _patch(api, target, {"authorization": None}).status_code == 422


def test_patch_cannot_move_target_to_another_project(
    api: TestClient, target: dict[str, Any]
) -> None:
    other = create_project(api, "Other")
    resp = _patch(api, target, {"project_id": other["id"]})
    assert resp.status_code == 422
    assert api.get(f"/api/v1/targets/{target['id']}").json()["project_id"] == target["project_id"]


def test_patch_cannot_set_server_controlled_fields(api: TestClient, target: dict[str, Any]) -> None:
    for body in (
        {"current_authorization_id": target["id"]},
        {"authorization": {**authorization_payload(), "acknowledged_at": "2020-01-01T00:00:00Z"}},
        {"authorization": {**authorization_payload(), "version": 99}},
    ):
        assert _patch(api, target, body).status_code == 422, body


@pytest.mark.parametrize("value", [1, "true", "yes", 0, None])
def test_acknowledge_must_be_boolean_true(
    api: TestClient, project: dict[str, Any], value: object
) -> None:
    payload = target_payload(authorization=authorization_payload(acknowledge=value))
    resp = api.post(f"/api/v1/projects/{project['id']}/targets", json=payload)
    assert resp.status_code == 422


@pytest.mark.parametrize(
    ("host", "base_url"),
    [
        ("0xa9fea9fe", "http://0xa9fea9fe/"),
        ("0xa9.0xfe.0xa9.0xfe", "http://0xa9.0xfe.0xa9.0xfe/"),
        ("2852039166", "http://2852039166/"),
    ],
)
@pytest.mark.parametrize("environment", ["local_lab", "authorized_external"])
def test_numeric_spellings_of_metadata_address_rejected(
    api: TestClient, project: dict[str, Any], host: str, base_url: str, environment: str
) -> None:
    payload = target_payload(base_url=base_url, in_scope_hosts=[host], environment=environment)
    resp = api.post(f"/api/v1/projects/{project['id']}/targets", json=payload)
    assert resp.status_code == 422
    assert resp.json()["field"] == "in_scope_hosts"


def test_port_zero_rejected(api: TestClient, project: dict[str, Any]) -> None:
    payload = target_payload(base_url="http://juice-shop:0/")
    resp = api.post(f"/api/v1/projects/{project['id']}/targets", json=payload)
    assert resp.status_code == 422
    assert resp.json()["field"] == "base_url"


# --- Request isolation and database conflicts --------------------------------------


@pytest.fixture
def name_check_bypassed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate the race where two requests both pass the name check before
    either commits: the service check says "free", so only the database's
    unique constraint stands in the way."""
    monkeypatch.setattr(TargetRepository, "name_exists", lambda *_, **__: False)


def test_concurrent_duplicate_creation_returns_generic_conflict(
    api: TestClient, project: dict[str, Any], name_check_bypassed: None
) -> None:
    create_target(api, project["id"])
    resp = api.post(f"/api/v1/projects/{project['id']}/targets", json=target_payload())

    assert resp.status_code == 409
    assert resp.json() == {
        "detail": "The request conflicts with existing data.",
        "code": "integrity_error",
        "field": None,
    }
    # No SQL, constraint names or driver details leak to the client.
    for leak in ("SQL", "INSERT", "uq_", "psycopg", "UniqueViolation", "targets"):
        assert leak not in resp.text
    assert len(api.get(f"/api/v1/projects/{project['id']}/targets").json()) == 1


def test_failed_request_does_not_leak_changes_into_later_requests(
    api: TestClient, project: dict[str, Any], name_check_bypassed: None
) -> None:
    first = create_target(api, project["id"], name="First")
    second = create_target(api, project["id"], name="Second")

    # The rename is flushed to the database before the unique constraint fails it.
    resp = _patch(api, second, {"name": "First", "authorization": authorization_payload()})
    assert resp.status_code == 409

    # A later, unrelated request commits; the failed request's changes must not ride along.
    assert (
        api.patch(f"/api/v1/projects/{project['id']}", json={"description": "x"}).status_code == 200
    )
    assert api.get(f"/api/v1/targets/{second['id']}").json()["name"] == "Second"
    assert len(_history(api, second)) == 1
    assert api.get(f"/api/v1/targets/{first['id']}").json()["name"] == "First"


def test_validation_failure_mid_update_changes_nothing(
    api: TestClient, target: dict[str, Any]
) -> None:
    resp = _patch(
        api,
        target,
        {"name": "Renamed", "in_scope_hosts": ["other"], "authorization": authorization_payload()},
    )
    assert resp.status_code == 422
    after = api.get(f"/api/v1/targets/{target['id']}").json()
    assert after["name"] == target["name"]
    assert after["authorization"] == target["authorization"]


def test_history_of_missing_target_is_404(api: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert api.get(f"/api/v1/targets/{missing}/authorizations").status_code == 404
    assert api.patch(f"/api/v1/targets/{missing}", json={"name": "x"}).status_code == 404
    assert api.delete(f"/api/v1/targets/{missing}").status_code == 404


def test_authorization_window_must_not_already_be_over_on_reauthorization(
    api: TestClient, target: dict[str, Any]
) -> None:
    resp = _patch(
        api,
        target,
        {
            "authorization": authorization_payload(
                valid_from=(NOW - timedelta(days=5)).isoformat(),
                valid_until=(NOW - timedelta(days=1)).isoformat(),
            )
        },
    )
    assert resp.status_code == 422
    assert len(_history(api, target)) == 1
