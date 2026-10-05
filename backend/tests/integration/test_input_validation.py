"""NUL characters in input are a validation error (422), not a database error.

PostgreSQL text cannot hold U+0000, so before this check any request carrying
one reached the database and failed with an unhandled DataError (HTTP 500).
Other control characters are valid text and are stored exactly as given.
"""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import create_assessment, create_project, create_target

pytestmark = pytest.mark.integration

LEAKS = ("Traceback", "DataError", "psycopg", "PostgreSQL", "Internal Server Error")


def assert_nul_rejected(resp_json: object, loc: list[str | int]) -> None:
    assert isinstance(resp_json, dict)
    errors = resp_json["detail"]
    assert isinstance(errors, list)
    nul = [e for e in errors if e["type"] == "nul_character"]
    assert [e["loc"] for e in nul] == [loc]
    assert nul[0]["msg"] == "Text must not contain NUL (U+0000) characters"


def test_nul_in_a_body_field_is_a_422(api: TestClient) -> None:
    responses = [api.post("/api/v1/projects", json={"name": "lab\x00name"}) for _ in range(2)]
    for resp in responses:
        assert resp.status_code == 422
        assert_nul_rejected(resp.json(), ["body", "name"])
        assert not any(leak in resp.text for leak in LEAKS)
    assert responses[0].json() == responses[1].json()  # deterministic
    assert api.get("/api/v1/projects").json() == []  # nothing was created


def test_nul_in_optional_and_patched_fields(api: TestClient) -> None:
    resp = api.post("/api/v1/projects", json={"name": "ok", "description": "a\x00b"})
    assert resp.status_code == 422
    assert_nul_rejected(resp.json(), ["body", "description"])

    project = create_project(api)
    resp = api.patch(f"/api/v1/projects/{project['id']}", json={"description": "\x00"})
    assert resp.status_code == 422
    assert_nul_rejected(resp.json(), ["body", "description"])
    assert api.get(f"/api/v1/projects/{project['id']}").json() == project


def test_nul_inside_lists_and_nested_objects(api: TestClient) -> None:
    project = create_project(api)
    base: dict[str, Any] = {
        "name": "Lab",
        "base_url": "http://lab-target/",
        "environment": "local_lab",
        "in_scope_hosts": ["lab-target"],
        "authorization": {
            "authorized_by": "Owner",
            "reference": "REF-1",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2030-01-01T00:00:00Z",
            "acknowledged_by": "Tester",
            "acknowledge": True,
        },
    }
    url = f"/api/v1/projects/{project['id']}/targets"
    resp = api.post(url, json={**base, "excluded_paths": ["/ok", "/a\x00b"]})
    assert resp.status_code == 422
    assert_nul_rejected(resp.json(), ["body", "excluded_paths"])
    resp = api.post(
        url, json={**base, "authorization": {**base["authorization"], "notes": "x\x00"}}
    )
    assert resp.status_code == 422
    assert_nul_rejected(resp.json(), ["body", "authorization"])


def test_nul_in_a_text_query_filter_is_a_422(api: TestClient) -> None:
    project = create_project(api)
    target = create_target(api, project["id"])
    assessment = create_assessment(api, target["id"])
    assert api.post(f"/api/v1/assessments/{assessment['id']}/start").status_code == 200
    scan = api.post(f"/api/v1/assessments/{assessment['id']}/scans", json={}).json()["id"]
    for name in ("method", "source", "skip_reason"):
        resp = api.get(f"/api/v1/scans/{scan}/endpoints", params={name: "a\x00b"})
        assert resp.status_code == 422, name
        assert_nul_rejected(resp.json(), ["query", name])
    # Without the NUL the filter is accepted.
    assert api.get(f"/api/v1/scans/{scan}/endpoints", params={"method": "GET"}).json() == []
    # A scan the caller cannot see is not found before any query validation
    # (Phase 9 M4: authorization runs first, so validation reveals nothing).
    missing = api.get(f"/api/v1/scans/{uuid.uuid4()}/endpoints", params={"method": "a\x00b"})
    assert missing.status_code == 404


@pytest.mark.parametrize(
    "name",
    [
        "bell\x07 and tab\t",  # control characters other than NUL stay valid
        "rlo \u202etxt.exe",  # bidi controls are stored, not stripped
        "Café 東京 🚀 \u2013 ü",  # ordinary Unicode
        "\x01\x1f\x7f",
    ],
)
def test_other_text_is_stored_exactly(api: TestClient, name: str) -> None:
    resp = api.post("/api/v1/projects", json={"name": name, "description": name})
    assert resp.status_code == 201, resp.text
    stored = api.get(f"/api/v1/projects/{resp.json()['id']}").json()
    assert stored["name"] == name.strip()
    assert stored["description"] == name
