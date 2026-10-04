import uuid

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import create_project, create_target

pytestmark = pytest.mark.integration

URL = "/api/v1/projects"


def test_create_get_list_project(api: TestClient) -> None:
    created = create_project(api, "Portfolio lab")
    assert created["name"] == "Portfolio lab"
    assert created["description"] is None

    assert api.get(f"{URL}/{created['id']}").json() == created
    assert [p["id"] for p in api.get(URL).json()] == [created["id"]]


def test_name_is_trimmed_and_unique(api: TestClient) -> None:
    create_project(api, "Lab")
    resp = api.post(URL, json={"name": "  Lab  "})
    assert resp.status_code == 409
    assert resp.json() == {
        "detail": "a project named 'Lab' already exists",
        "code": "conflict",
        "field": "name",
    }


def test_update_project(api: TestClient) -> None:
    project = create_project(api)
    resp = api.patch(f"{URL}/{project['id']}", json={"description": "Docker lab targets"})
    assert resp.status_code == 200
    assert resp.json()["description"] == "Docker lab targets"
    assert resp.json()["name"] == project["name"]

    # description is nullable; name is not.
    assert api.patch(f"{URL}/{project['id']}", json={"description": None}).status_code == 200
    assert api.patch(f"{URL}/{project['id']}", json={"name": None}).status_code == 422


def test_rename_to_existing_name_conflicts(api: TestClient) -> None:
    create_project(api, "A")
    b = create_project(api, "B")
    assert api.patch(f"{URL}/{b['id']}", json={"name": "A"}).status_code == 409


def test_unknown_fields_are_rejected(api: TestClient) -> None:
    resp = api.post(URL, json={"name": "X", "created_by": "attacker"})
    assert resp.status_code == 422


def test_missing_project_is_404(api: TestClient) -> None:
    resp = api.get(f"{URL}/{uuid.uuid4()}")
    assert resp.status_code == 404
    assert resp.json()["code"] == "not_found"


def test_delete_project(api: TestClient) -> None:
    project = create_project(api)
    assert api.delete(f"{URL}/{project['id']}").status_code == 204
    assert api.get(f"{URL}/{project['id']}").status_code == 404


def test_cannot_delete_project_with_targets(api: TestClient) -> None:
    project = create_project(api)
    create_target(api, project["id"])
    resp = api.delete(f"{URL}/{project['id']}")
    assert resp.status_code == 409
    assert api.get(f"{URL}/{project['id']}").status_code == 200


def test_pagination(api: TestClient) -> None:
    for i in range(3):
        create_project(api, f"P{i}")
    assert len(api.get(URL, params={"limit": 2}).json()) == 2
    assert len(api.get(URL, params={"limit": 2, "offset": 2}).json()) == 1
    assert api.get(URL, params={"limit": 101}).status_code == 422
