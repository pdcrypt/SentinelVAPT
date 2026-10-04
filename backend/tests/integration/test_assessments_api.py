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
)

pytestmark = pytest.mark.integration


@pytest.fixture
def project(api: TestClient) -> dict[str, Any]:
    return create_project(api)


@pytest.fixture
def target(api: TestClient, project: dict[str, Any]) -> dict[str, Any]:
    return create_target(api, project["id"])


def _url(assessment: dict[str, Any], action: str = "") -> str:
    return f"/api/v1/assessments/{assessment['id']}{action}"


def test_create_and_get_assessment(api: TestClient, target: dict[str, Any]) -> None:
    assessment = create_assessment(api, target["id"])
    assert assessment["status"] == "planned"
    assert assessment["target_id"] == target["id"]
    assert assessment["started_at"] is None
    assert api.get(_url(assessment)).json() == assessment


def test_status_cannot_be_set_directly(api: TestClient, target: dict[str, Any]) -> None:
    url = f"/api/v1/targets/{target['id']}/assessments"
    assert api.post(url, json={"name": "X", "status": "completed"}).status_code == 422
    assessment = create_assessment(api, target["id"])
    assert api.patch(_url(assessment), json={"status": "completed"}).status_code == 422


def test_full_lifecycle(api: TestClient, target: dict[str, Any], clock: FrozenClock) -> None:
    assessment = create_assessment(api, target["id"])

    started = api.post(_url(assessment, "/start"))
    assert started.status_code == 200
    assert started.json()["status"] == "in_progress"
    assert started.json()["started_at"].startswith("2026-10-04T12:00:00")

    clock.advance(timedelta(hours=2))
    completed = api.post(_url(assessment, "/complete"))
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"
    assert completed.json()["completed_at"].startswith("2026-10-04T14:00:00")


@pytest.mark.parametrize(
    ("setup", "action"),
    [
        ([], "/complete"),  # planned -> completed skips in_progress
        (["/start", "/complete"], "/start"),  # completed is terminal
        (["/cancel"], "/start"),  # cancelled is terminal
        (["/start", "/complete"], "/cancel"),
    ],
)
def test_invalid_transitions(
    api: TestClient, target: dict[str, Any], setup: list[str], action: str
) -> None:
    assessment = create_assessment(api, target["id"])
    for step in setup:
        assert api.post(_url(assessment, step)).status_code == 200
    resp = api.post(_url(assessment, action))
    assert resp.status_code == 409
    assert resp.json()["code"] == "invalid_state_transition"


def test_cannot_start_before_authorization_window(
    api: TestClient, project: dict[str, Any], clock: FrozenClock
) -> None:
    target = create_target(
        api,
        project["id"],
        authorization=authorization_payload(
            valid_from=(NOW + timedelta(days=1)).isoformat(),
            valid_until=(NOW + timedelta(days=5)).isoformat(),
        ),
    )
    assessment = create_assessment(api, target["id"])  # planning ahead is allowed

    resp = api.post(_url(assessment, "/start"))
    assert resp.status_code == 409
    assert resp.json()["code"] == "target_authorization_invalid"
    assert "pending" in resp.json()["detail"]

    clock.advance(timedelta(days=2))
    assert api.post(_url(assessment, "/start")).status_code == 200


def test_expired_authorization_blocks_create_and_start(
    api: TestClient, target: dict[str, Any], clock: FrozenClock
) -> None:
    planned = create_assessment(api, target["id"])
    clock.advance(timedelta(days=31))

    resp = api.post(f"/api/v1/targets/{target['id']}/assessments", json={"name": "Late"})
    assert resp.status_code == 409
    assert resp.json()["code"] == "target_authorization_invalid"

    resp = api.post(_url(planned, "/start"))
    assert resp.status_code == 409
    assert "expired" in resp.json()["detail"]

    # Cancelling is still allowed: it never touches the target.
    assert api.post(_url(planned, "/cancel")).status_code == 200


def test_update_assessment(api: TestClient, target: dict[str, Any]) -> None:
    assessment = create_assessment(api, target["id"])
    resp = api.patch(_url(assessment), json={"name": "Renamed", "description": "notes"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "Renamed"
    assert resp.json()["description"] == "notes"


def test_delete_rules(api: TestClient, target: dict[str, Any]) -> None:
    planned = create_assessment(api, target["id"], "planned")
    assert api.delete(_url(planned)).status_code == 204

    running = create_assessment(api, target["id"], "running")
    api.post(_url(running, "/start"))
    assert api.delete(_url(running)).status_code == 409

    api.post(_url(running, "/cancel"))
    assert api.delete(_url(running)).status_code == 204


def test_list_by_target_and_project(
    api: TestClient, project: dict[str, Any], target: dict[str, Any]
) -> None:
    second_target = create_target(api, project["id"], name="Second")
    a = create_assessment(api, target["id"], "A")
    b = create_assessment(api, second_target["id"], "B")

    other_project = create_project(api, "Other")
    create_assessment(api, create_target(api, other_project["id"])["id"], "C")

    by_target = api.get(f"/api/v1/targets/{target['id']}/assessments").json()
    assert [x["id"] for x in by_target] == [a["id"]]

    by_project = api.get(f"/api/v1/projects/{project['id']}/assessments").json()
    # Rows created in one transaction share created_at, so compare as sets.
    assert {x["id"] for x in by_project} == {a["id"], b["id"]}


def test_missing_parents_are_404(api: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert api.post(f"/api/v1/targets/{missing}/assessments", json={"name": "X"}).status_code == 404
    assert api.get(f"/api/v1/targets/{missing}/assessments").status_code == 404
    assert api.get(f"/api/v1/projects/{missing}/assessments").status_code == 404
    assert api.post(f"/api/v1/assessments/{missing}/start").status_code == 404


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (timedelta(seconds=-1), 200),  # last second of the window
        (timedelta(0), 409),  # valid_until itself is outside the window
    ],
)
def test_start_at_authorization_expiry_boundary(
    api: TestClient,
    target: dict[str, Any],
    clock: FrozenClock,
    offset: timedelta,
    expected: int,
) -> None:
    assessment = create_assessment(api, target["id"])
    valid_until = NOW + timedelta(days=30)  # from authorization_payload()
    clock.now = valid_until + offset
    resp = api.post(_url(assessment, "/start"))
    assert resp.status_code == expected, resp.text
    if expected == 409:
        assert resp.json()["code"] == "target_authorization_invalid"


def test_patch_assessment_rejects_null_name(api: TestClient, target: dict[str, Any]) -> None:
    assessment = create_assessment(api, target["id"])
    assert api.patch(_url(assessment), json={"name": None}).status_code == 422
    assert api.patch(_url(assessment), json={"description": None}).status_code == 200
    assert api.get(_url(assessment)).json()["name"] == assessment["name"]


def test_patch_assessment_cannot_change_target_or_authorization(
    api: TestClient, project: dict[str, Any], target: dict[str, Any]
) -> None:
    assessment = create_assessment(api, target["id"])
    other = create_target(api, project["id"], name="Other")
    for body in (
        {"target_id": other["id"]},
        {"authorization_id": other["authorization"]["id"]},
    ):
        assert api.patch(_url(assessment), json=body).status_code == 422
