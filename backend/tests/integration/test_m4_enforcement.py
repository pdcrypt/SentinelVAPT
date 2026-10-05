"""Phase 9 M4: authorization enforced on every product route, through real
sessions (no principal override), against two fully populated projects.

Sections: the role x route matrix, sessions, the password-change gate, IDOR
(including nested and body id substitution), list filtering, project
creation, privilege escalation, target authorization independence, workers,
actor identity and concurrency."""

import threading
import time
import uuid
from collections.abc import Callable, Mapping
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text

from app.core.authz import (
    Authenticated,
    GlobalAccess,
    Permission,
    ProjectAccess,
    project_role_grants,
)
from app.models.enums import ProjectRole
from tests.integration.auth_support import PASSWORD, Live, bearer, login
from tests.integration.conftest import FrozenClock
from tests.integration.m4_support import (
    FORBIDDEN,
    MEMBERS,
    PASSWORD_CHANGE,
    World,
    not_found,
    world,
)
from tests.unit.test_route_inventory import EXPECTED

pytestmark = pytest.mark.integration

__all__ = ["world"]

P = Permission
API = "/api/v1"
ALL_ACTORS: list[str | None] = [None, *MEMBERS, "admin"]
PROJECT_ROUTES = sorted(k for k, d in EXPECTED.items() if isinstance(d, ProjectAccess))
MUTATING = [k for k in PROJECT_ROUTES if k[0] != "GET"]
TARGET_CREATE = ("POST", "/api/v1/projects/{project_id}/targets")
RETEST_REPORT_CREATE = (
    "POST",
    "/api/v1/assessments/{assessment_id}/comparisons/{comparison_id}/reports",
)
RETEST_REPORT_BODY = {
    "title": "Retest report",
    "prepared_by": "Tester",
    "formats": ["json", "html"],
}


def unique(prefix: str = "m4") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def target_body(w: World, **overrides: Any) -> dict[str, Any]:
    now = w.live.clock()
    authorization = {
        "authorized_by": "Lab Owner",
        "reference": "LAB-M4",
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=30)).isoformat(),
        "acknowledged_by": "Tester",
        "acknowledge": True,
    }
    body = {
        "name": unique("target"),
        "base_url": "http://lab-target/",
        "environment": "local_lab",
        "in_scope_hosts": ["lab-target"],
        "authorization": authorization,
    }
    authorization.update(overrides.pop("authorization", {}))
    body.update(overrides)
    return body


# How to call each state-changing route without disturbing the shared world,
# and what a permitted member gets: success where that is harmless, otherwise
# the existing lifecycle answer (the baseline assessment is completed).
Body = Callable[[World, Mapping[str, str]], Any]
PROBES: dict[tuple[str, str], tuple[Body | None, int]] = {
    ("PATCH", "/api/v1/projects/{project_id}"): (lambda w, i: {}, 200),
    ("DELETE", "/api/v1/projects/{project_id}"): (None, 409),  # it has targets
    TARGET_CREATE: (lambda w, i: target_body(w), 201),
    ("PATCH", "/api/v1/targets/{target_id}"): (lambda w, i: {}, 200),
    ("DELETE", "/api/v1/targets/{target_id}"): (None, 409),  # it has assessments
    ("POST", "/api/v1/targets/{target_id}/assessments"): (lambda w, i: {"name": unique()}, 201),
    ("PATCH", "/api/v1/assessments/{assessment_id}"): (lambda w, i: {}, 200),
    ("DELETE", "/api/v1/assessments/{assessment_id}"): (None, 409),  # completed
    ("POST", "/api/v1/assessments/{assessment_id}/start"): (None, 409),
    ("POST", "/api/v1/assessments/{assessment_id}/complete"): (None, 409),
    ("POST", "/api/v1/assessments/{assessment_id}/cancel"): (None, 409),
    ("POST", "/api/v1/assessments/{assessment_id}/scans"): (lambda w, i: {}, 409),
    ("POST", "/api/v1/assessments/{assessment_id}/reports"): (lambda w, i: {"bogus": 1}, 422),
    ("POST", "/api/v1/assessments/{assessment_id}/retests"): (lambda w, i: {"bogus": 1}, 422),
    ("POST", "/api/v1/assessments/{assessment_id}/comparisons"): (
        lambda w, i: {"scan_id": i["scan"]},
        409,  # not a retest
    ),
    RETEST_REPORT_CREATE: (lambda w, i: RETEST_REPORT_BODY, 200),  # identical: the existing one
    ("POST", "/api/v1/scans/{scan_id}/cancel"): (None, 409),  # completed
    ("POST", "/api/v1/findings/{finding_id}/triage"): (
        lambda w, i: {"status": "open", "triaged_by": "x"},
        409,  # already open
    ),
}
# The exact lifecycle answer a permitted member gets from each probe above, so
# that an unrelated 409 (e.g. a superseded authorization) cannot stand in for
# the rule being checked.
INVALID_TRANSITION = {"code": "invalid_state_transition"}
EXTRA_FIELD = {"detail_type": "extra_forbidden"}
LIFECYCLE: dict[tuple[str, str], dict[str, str]] = {
    ("DELETE", "/api/v1/projects/{project_id}"): {"code": "conflict"},
    ("DELETE", "/api/v1/targets/{target_id}"): {"code": "conflict"},
    ("DELETE", "/api/v1/assessments/{assessment_id}"): {"code": "conflict"},
    ("POST", "/api/v1/assessments/{assessment_id}/start"): INVALID_TRANSITION,
    ("POST", "/api/v1/assessments/{assessment_id}/complete"): INVALID_TRANSITION,
    ("POST", "/api/v1/assessments/{assessment_id}/cancel"): INVALID_TRANSITION,
    ("POST", "/api/v1/assessments/{assessment_id}/scans"): {
        "code": "scan_not_allowed",
        "reason": "assessment_not_in_progress",
    },
    ("POST", "/api/v1/assessments/{assessment_id}/reports"): EXTRA_FIELD,
    ("POST", "/api/v1/assessments/{assessment_id}/retests"): EXTRA_FIELD,
    ("POST", "/api/v1/assessments/{assessment_id}/comparisons"): {
        "code": "comparison_not_allowed",
        "reason": "not_a_retest",
    },
    ("POST", "/api/v1/scans/{scan_id}/cancel"): INVALID_TRANSITION,
    ("POST", "/api/v1/findings/{finding_id}/triage"): INVALID_TRANSITION,
}


def assert_lifecycle(key: tuple[str, str], resp: Any) -> None:
    expected_fields = LIFECYCLE.get(key)
    if expected_fields is None:
        return
    body = resp.json()
    for name, value in expected_fields.items():
        if name == "detail_type":
            assert value in {e["type"] for e in body["detail"]}, (key, body)
        else:
            assert body.get(name) == value, (key, name, body)


PARAMS = {
    "project_id": "project",
    "target_id": "target",
    "assessment_id": "assessment",
    "scan_id": "scan",
    "evidence_id": "evidence",
    "finding_id": "finding",
    "comparison_id": "comparison",
    "fingerprint": "fingerprint",
}


def fill(key: tuple[str, str], ids: Mapping[str, str]) -> str:
    path = key[1]
    values = {name: ids[ref] for name, ref in PARAMS.items()}
    values["report_id"] = ids["retest_report" if "/retest-reports/" in path else "report"]
    values["fmt"] = "json"
    if key == RETEST_REPORT_CREATE:
        values["assessment_id"] = ids["retest"]
    return path.format(**values)


def random_ids() -> dict[str, str]:
    ids = {
        name: str(uuid.uuid4())
        for name in (
            "project",
            "target",
            "assessment",
            "retest",
            "scan",
            "evidence",
            "finding",
            "comparison",
            "report",
            "retest_report",
        )
    }
    ids["fingerprint"] = uuid.uuid4().hex * 2
    return ids


def probe(w: World, actor: str | None, key: tuple[str, str], ids: Mapping[str, str]) -> Any:
    make_body, _ = PROBES.get(key, (None, 200))
    body = make_body(w, ids) if make_body else None
    return w.request(actor, key[0], fill(key, ids), body)


def required(key: tuple[str, str]) -> set[Permission]:
    descriptor = EXPECTED[key]
    assert isinstance(descriptor, ProjectAccess)
    extra = {P.TARGET_AUTHORIZE} if key == TARGET_CREATE else set()
    return {descriptor.permission} | extra


def expected(actor: str | None, key: tuple[str, str]) -> tuple[int, dict[str, Any] | None]:
    descriptor = EXPECTED[key]
    assert isinstance(descriptor, ProjectAccess)
    if actor is None:
        return 401, None
    if actor == "pending":
        return 403, PASSWORD_CHANGE
    side_role = MEMBERS.get(actor)
    if side_role is None or side_role[0] != "a":
        return 404, not_found(descriptor.resource_type.not_found)
    if all(project_role_grants(side_role[1], p) for p in required(key)):
        return PROBES.get(key, (None, 200))[1], None
    return 403, FORBIDDEN


# --- the role x route matrix --------------------------------------------------------------------


@pytest.mark.parametrize("key", PROJECT_ROUTES, ids=lambda k: f"{k[0]} {k[1]}")
def test_route_authorization_matrix(world: World, key: tuple[str, str]) -> None:
    """Every project route, every kind of caller: anonymous 401, pending
    password 403, non-member and admin 404, member without the permission
    403, member with it the route's own result (success or lifecycle)."""
    for actor in ALL_ACTORS:
        status, body = expected(actor, key)
        resp = probe(world, actor, key, world.ids["a"])
        assert resp.status_code == status, (actor, resp.text)
        if body is not None:
            assert resp.json() == body, actor
        elif actor is not None and status >= 400:
            assert_lifecycle(key, resp)
        if status == 401:
            assert resp.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "key", sorted(k for k, d in EXPECTED.items() if not isinstance(d, ProjectAccess))
)
def test_public_authenticated_and_global_routes(world: World, key: tuple[str, str]) -> None:
    descriptor = EXPECTED[key]
    if key == ("POST", "/api/v1/projects"):
        return  # see test_project_creation_makes_the_creator_the_owner
    if key[1].startswith("/api/v1/auth/") and key[1] != "/api/v1/auth/me":
        return  # login, logout and password change are covered by the M2 suite
    if key[1] == "/api/v1/health/ready":
        return  # pings the configured database; public access is covered by the unit tests
    for actor in ALL_ACTORS:
        resp = world.request(actor, key[0], key[1])
        if isinstance(descriptor, Authenticated | GlobalAccess) and actor is None:
            assert resp.status_code == 401, key
        elif (
            isinstance(descriptor, GlobalAccess | Authenticated)
            and actor == "pending"
            and not (
                isinstance(descriptor, Authenticated) and descriptor.allow_password_change_pending
            )
        ):
            assert (resp.status_code, resp.json()) == (403, PASSWORD_CHANGE), key
        else:
            assert resp.status_code == 200, (key, actor, resp.text)


# --- sessions ------------------------------------------------------------------------------------


def test_invalid_revoked_and_expired_sessions_are_rejected(world: World) -> None:
    paths = [f"{API}/projects", f"{API}/rules", f"{API}/projects/{world.ids['a']['project']}"]
    viewer = world.users["viewer_a"].username

    def rejected(client: Any, token: str) -> None:
        for path in paths:
            resp = client.get(path, headers=bearer(token))
            assert resp.status_code == 401, path
            assert resp.headers["WWW-Authenticate"] == "Bearer"

    rejected(world.client, "x" * 43)
    token = login(world.client, viewer).json()["token"]
    assert world.client.get(paths[2], headers=bearer(token)).status_code == 200
    assert world.client.post(f"{API}/auth/logout", headers=bearer(token)).status_code == 204
    rejected(world.client, token)
    # Expiry: a separate clock, so the shared sessions are not affected.
    other = Live(
        world.live.engine, world.live.factory, world.live.settings, FrozenClock(world.live.clock())
    )
    client = other.client()
    try:
        token = login(client, viewer).json()["token"]
        assert client.get(paths[2], headers=bearer(token)).status_code == 200
        other.advance(hours=13)
        rejected(client, token)
    finally:
        client.__exit__(None, None, None)
    # A cookie is never a credential.
    world.client.cookies.set("sv_session", world.tokens["owner_a"])
    try:
        assert world.client.get(paths[0]).status_code == 401
    finally:
        world.client.cookies.clear()


# --- password-change gate ------------------------------------------------------------------------


def test_password_change_gate_blocks_everything_but_the_account_routes(world: World) -> None:
    """Covered route by route in the matrix; here the account routes and the
    full cycle: blocked, change the password, new session, access restored."""
    for key, descriptor in EXPECTED.items():
        if key[1].startswith("/api/v1/health") or key == ("POST", "/api/v1/auth/login"):
            continue
        if isinstance(descriptor, Authenticated) and descriptor.allow_password_change_pending:
            continue
        resp = world.request(
            "pending",
            key[0],
            fill(key, world.ids["a"]) if isinstance(descriptor, ProjectAccess) else key[1],
        )
        assert (resp.status_code, resp.json()) == (403, PASSWORD_CHANGE), key
    assert world.request("pending", "GET", f"{API}/auth/me").json()["user"]["must_change_password"]

    user = world.live.user(unique("changer"))
    world.add_member("a", user.id, ProjectRole.VIEWER)
    with world.live.engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET must_change_password = true WHERE id = :u"), {"u": user.id}
        )
    old = login(world.client, user.username).json()["token"]
    target = f"{API}/targets/{world.ids['a']['target']}"
    assert world.client.get(target, headers=bearer(old)).json() == PASSWORD_CHANGE
    changed = world.client.post(
        f"{API}/auth/password",
        headers=bearer(old),
        json={"current_password": PASSWORD, "new_password": "a-new-lab-password-5678"},
    )
    assert changed.status_code == 200, changed.text
    new = changed.json()["token"]
    assert changed.json()["user"]["must_change_password"] is False
    assert world.client.get(target, headers=bearer(old)).status_code == 401  # rotated
    assert world.client.get(target, headers=bearer(new)).status_code == 200


# --- IDOR ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("key", PROJECT_ROUTES, ids=lambda k: f"{k[0]} {k[1]}")
def test_another_projects_ids_are_indistinguishable_from_missing_ones(
    world: World, key: tuple[str, str]
) -> None:
    descriptor = EXPECTED[key]
    assert isinstance(descriptor, ProjectAccess)
    missing = not_found(descriptor.resource_type.not_found)
    for actor in ("owner_a", "operator_a", "viewer_a"):
        foreign = probe(world, actor, key, world.ids["b"])
        absent = probe(world, actor, key, random_ids())
        assert (foreign.status_code, foreign.json()) == (404, missing), actor
        assert (absent.status_code, absent.json()) == (404, missing), actor


def test_nested_and_body_id_substitution(world: World) -> None:
    a, b = world.ids["a"], world.ids["b"]
    owner = "owner_a"
    rnd = str(uuid.uuid4())

    def same_404(*paths_and_bodies: tuple[str, str, Any]) -> None:
        bodies = []
        for method, path, body in paths_and_bodies:
            resp = world.request(owner, method, path, body)
            assert resp.status_code == 404, (path, resp.text)
            bodies.append(resp.json())
        assert all(x == bodies[0] for x in bodies), bodies

    # Project A retest + project B comparison (and the reverse).
    same_404(
        (
            "POST",
            f"{API}/assessments/{a['retest']}/comparisons/{b['comparison']}/reports",
            RETEST_REPORT_BODY,
        ),
        ("POST", f"{API}/assessments/{a['retest']}/comparisons/{rnd}/reports", RETEST_REPORT_BODY),
        (
            "POST",
            f"{API}/assessments/{b['retest']}/comparisons/{a['comparison']}/reports",
            RETEST_REPORT_BODY,
        ),
    )
    # Project A assessment + project B scan in the body.
    report = {"kind": "draft", "title": "x", "prepared_by": "y", "formats": ["json"]}
    same_404(
        ("POST", f"{API}/assessments/{a['assessment']}/reports", {**report, "scan_id": b["scan"]}),
        ("POST", f"{API}/assessments/{a['assessment']}/reports", {**report, "scan_id": rnd}),
    )
    # Project A retest + project B baseline (C is completed and has no retest yet).
    same_404(
        (
            "POST",
            f"{API}/assessments/{a['retest_c']}/retests",
            {"name": unique(), "baseline_scan_id": b["scan"]},
        ),
        (
            "POST",
            f"{API}/assessments/{a['retest_c']}/retests",
            {"name": unique(), "baseline_scan_id": rnd},
        ),
    )
    # Project A comparison request + project B scan.
    same_404(
        ("POST", f"{API}/assessments/{a['retest']}/comparisons", {"scan_id": b["scan_b"]}),
        ("POST", f"{API}/assessments/{a['retest']}/comparisons", {"scan_id": rnd}),
    )
    # Project B report artifacts, previews and evidence by id alone.
    for path in (
        f"/reports/{b['report']}/artifacts/json",
        f"/reports/{b['report']}/preview",
        f"/retest-reports/{b['retest_report']}/artifacts/json",
        f"/retest-reports/{b['retest_report']}/preview",
        f"/evidence/{b['report_evidence']}",
        f"/evidence/{b['coverage_evidence']}",
        f"/evidence/{b['retest_report_evidence']}",
        f"/comparisons/{b['coverage_comparison']}/records/{b['coverage_fingerprint']}",
    ):
        assert world.request(owner, "GET", f"{API}{path}").status_code == 404, path
    # Nothing was created by any of these requests.
    with world.live.engine.connect() as conn:
        assert (
            conn.scalar(
                text("SELECT count(*) FROM assessments WHERE retest_of_assessment_id = :c"),
                {"c": a["retest_c"]},
            )
            == 0
        )


def test_client_supplied_project_ids_never_steer_authorization(world: World) -> None:
    a, b = world.ids["a"], world.ids["b"]
    resp = world.request(
        "owner_a",
        "GET",
        f"{API}/targets/{b['target']}",
        params={"project_id": a["project"]},
        headers={"X-Project-Id": a["project"]},
    )
    assert resp.status_code == 404
    # A body cannot name a project (or an owner, or a role): unknown fields are refused.
    for extra in ({"project_id": b["project"]}, {"owner_id": str(world.users["owner_b"].id)}):
        resp = world.request(
            "owner_a",
            "POST",
            f"{API}/projects/{a['project']}/targets",
            {**target_body(world), **extra},
        )
        assert resp.status_code == 422, extra
    for extra in (
        {"owner_id": str(world.users["owner_b"].id)},
        {"role": "owner"},
        {"created_by_user_id": str(world.users["owner_b"].id)},
    ):
        resp = world.request("owner_a", "POST", f"{API}/projects", {"name": unique(), **extra})
        assert resp.status_code == 422, extra


# --- lists ---------------------------------------------------------------------------------------


def test_project_list_contains_only_member_projects(world: World) -> None:
    a, b = world.ids["a"]["project"], world.ids["b"]["project"]
    expected_sets = {
        "owner_a": {a},
        "operator_a": {a},
        "viewer_a": {a},
        "owner_b": {b},
        "operator_b": {b},
        "viewer_b": {b},
        "admin": set(),
    }
    for actor, projects in expected_sets.items():
        listed = world.request(actor, "GET", f"{API}/projects", params={"limit": 100}).json()
        assert {p["id"] for p in listed} == projects, actor


def test_no_list_or_detail_leaks_another_projects_resources(world: World) -> None:
    """Every readable route of project A, for every member of A: no id of
    project B appears anywhere in the response."""
    b_ids = {v for k, v in world.ids["b"].items() if "fingerprint" not in k and "role" not in k}
    for key in PROJECT_ROUTES:
        if key[0] != "GET":
            continue
        for actor in ("owner_a", "operator_a", "viewer_a"):
            resp = world.request(
                actor,
                "GET",
                fill(key, world.ids["a"]),
                params=(
                    {"limit": 100} if "{fmt}" not in key[1] and "preview" not in key[1] else None
                ),
            )
            assert resp.status_code == 200, (key, actor)
            body = resp.content.decode("utf-8", "replace")
            assert not [x for x in b_ids if x in body], key


# --- project creation ----------------------------------------------------------------------------


def test_project_creation_makes_the_creator_the_owner(world: World) -> None:
    for global_role in ("user", "admin"):
        user = world.live.user(unique("creator"), role=global_role)  # type: ignore[arg-type]
        token = login(world.client, user.username).json()["token"]
        resp = world.client.post(
            f"{API}/projects", headers=bearer(token), json={"name": unique("project")}
        )
        assert resp.status_code == 201, resp.text
        project = uuid.UUID(resp.json()["id"])
        world.created_projects.append(project)
        with world.live.engine.connect() as conn:
            members = conn.execute(
                text(
                    "SELECT user_id, role, created_by_user_id FROM "
                    "project_members WHERE project_id = :p"
                ),
                {"p": project},
            ).all()
        assert members == [(user.id, "owner", user.id)]
        listed = world.client.get(f"{API}/projects", headers=bearer(token)).json()
        assert [p["id"] for p in listed] == [str(project)]
        assert (
            world.client.get(f"{API}/projects/{project}", headers=bearer(token)).status_code == 200
        )
        # Nobody else sees it, including other admins and members of other projects.
        for actor in ("owner_a", "admin", "owner_b"):
            assert world.request(actor, "GET", f"{API}/projects/{project}").status_code == 404
    # Names are unique per member, and other users' names are never revealed.
    name = unique("shared-name")
    first = world.request("owner_a", "POST", f"{API}/projects", {"name": name})
    world.created_projects.append(uuid.UUID(first.json()["id"]))
    assert world.request("owner_a", "POST", f"{API}/projects", {"name": name}).status_code == 409
    other = world.request("owner_b", "POST", f"{API}/projects", {"name": name})
    assert other.status_code == 201
    world.created_projects.append(uuid.UUID(other.json()["id"]))
    assert world.request(None, "POST", f"{API}/projects", {"name": unique()}).status_code == 401
    pending = world.request("pending", "POST", f"{API}/projects", {"name": unique()})
    assert (pending.status_code, pending.json()) == (403, PASSWORD_CHANGE)


# --- privilege escalation ------------------------------------------------------------------------


def test_viewer_cannot_mutate(world: World) -> None:
    for key in MUTATING:
        resp = probe(world, "viewer_a", key, world.ids["a"])
        assert (resp.status_code, resp.json()) == (403, FORBIDDEN), key
    reauthorize = {"authorization": target_body(world)["authorization"]}
    resp = world.request(
        "viewer_a", "PATCH", f"{API}/targets/{world.ids['a']['target']}", reauthorize
    )
    assert resp.status_code == 403


OWNER_ONLY = [
    ("PATCH", "/api/v1/projects/{project_id}"),
    ("DELETE", "/api/v1/projects/{project_id}"),
    TARGET_CREATE,
    ("PATCH", "/api/v1/targets/{target_id}"),
    ("DELETE", "/api/v1/targets/{target_id}"),
    ("DELETE", "/api/v1/assessments/{assessment_id}"),
]


def test_operator_cannot_perform_owner_operations(world: World) -> None:
    for key in OWNER_ONLY:
        resp = probe(world, "operator_a", key, world.ids["a"])
        assert (resp.status_code, resp.json()) == (403, FORBIDDEN), key
    reauthorize = {"authorization": target_body(world)["authorization"]}
    resp = world.request(
        "operator_a", "PATCH", f"{API}/targets/{world.ids['a']['target']}", reauthorize
    )
    assert (resp.status_code, resp.json()) == (403, FORBIDDEN)
    # There is no membership API before M7; the role table already refuses it.
    assert not project_role_grants(ProjectRole.OPERATOR, P.MEMBERSHIP_MANAGE)
    assert not project_role_grants(ProjectRole.OPERATOR, P.TARGET_AUTHORIZE)
    assert not any(
        isinstance(d, ProjectAccess) and d.permission is P.MEMBERSHIP_MANAGE
        for d in EXPECTED.values()
    )


def test_admin_without_membership_cannot_access_project_resources(world: World) -> None:
    for side in ("a", "b"):
        for key in PROJECT_ROUTES:
            resp = probe(world, "admin", key, world.ids[side])
            assert resp.status_code == 404, key
    assert world.request("admin", "GET", f"{API}/projects").json() == []


def test_owner_operations_succeed_but_lifecycle_rules_still_apply(world: World) -> None:
    project = world.ids["a"]["project"]
    owner, operator = "owner_a", "operator_a"
    target = world.request(owner, "POST", f"{API}/projects/{project}/targets", target_body(world))
    assert target.status_code == 201, target.text
    tid = target.json()["id"]
    planned = world.request(owner, "POST", f"{API}/targets/{tid}/assessments", {"name": unique()})
    assert (
        world.request(owner, "DELETE", f"{API}/assessments/{planned.json()['id']}").status_code
        == 204
    )
    running = world.request(
        operator, "POST", f"{API}/targets/{tid}/assessments", {"name": unique()}
    ).json()["id"]
    # Permission is not lifecycle: an operator cannot scan a planned assessment.
    assert (
        world.request(operator, "POST", f"{API}/assessments/{running}/scans", {}).status_code == 409
    )
    assert world.request(operator, "POST", f"{API}/assessments/{running}/start").status_code == 200
    scan = world.request(operator, "POST", f"{API}/assessments/{running}/scans", {})
    assert scan.status_code == 201, scan.text
    # One active scan per assessment, whoever asks.
    assert world.request(owner, "POST", f"{API}/assessments/{running}/scans", {}).status_code == 409
    assert (
        world.request(operator, "POST", f"{API}/scans/{scan.json()['id']}/cancel").status_code
        == 200
    )
    # The owner cannot delete an in-progress assessment or a target with assessments.
    assert world.request(owner, "DELETE", f"{API}/assessments/{running}").status_code == 409
    assert world.request(owner, "DELETE", f"{API}/targets/{tid}").status_code == 409
    assert world.request(owner, "PATCH", f"{API}/projects/{project}", {}).status_code == 200


# --- target authorization stays separate ---------------------------------------------------


def test_scan_run_cannot_bypass_target_authorization(world: World) -> None:
    project = world.ids["a"]["project"]
    owner, operator = "owner_a", "operator_a"
    now = world.live.clock()
    body = target_body(
        world, authorization={"valid_until": (now + timedelta(minutes=1)).isoformat()}
    )
    tid = world.request(owner, "POST", f"{API}/projects/{project}/targets", body).json()["id"]
    aid = world.request(
        operator, "POST", f"{API}/targets/{tid}/assessments", {"name": unique()}
    ).json()["id"]
    assert world.request(operator, "POST", f"{API}/assessments/{aid}/start").status_code == 200
    world.live.advance(minutes=2)  # the target's authorization has now expired
    refused = world.request(operator, "POST", f"{API}/assessments/{aid}/scans", {})
    assert refused.status_code == 409, refused.text
    assert world.request(owner, "POST", f"{API}/assessments/{aid}/scans", {}).status_code == 409
    # A not-yet-valid authorization does not count either.
    future = target_body(
        world,
        authorization={
            "valid_from": (now + timedelta(days=1)).isoformat(),
            "valid_until": (now + timedelta(days=2)).isoformat(),
        },
    )
    patched = world.request(
        owner, "PATCH", f"{API}/targets/{tid}", {"authorization": future["authorization"]}
    )
    assert patched.status_code == 200, patched.text
    assert world.request(operator, "POST", f"{API}/assessments/{aid}/scans", {}).status_code == 409
    # Membership never replaces the acknowledgment, and only local_lab targets exist.
    no_ack = target_body(world, authorization={"acknowledge": False})
    assert (
        world.request(owner, "POST", f"{API}/projects/{project}/targets", no_ack).status_code == 422
    )
    external = target_body(world, environment="external")
    assert (
        world.request(owner, "POST", f"{API}/projects/{project}/targets", external).status_code
        == 422
    )


def test_target_authorization_text_grants_no_platform_access(world: World) -> None:
    project = world.ids["a"]["project"]
    outsider = world.users["viewer_b"].username
    body = target_body(
        world, authorization={"authorized_by": outsider, "acknowledged_by": outsider}
    )
    tid = world.request("owner_a", "POST", f"{API}/projects/{project}/targets", body).json()["id"]
    for path in (f"/targets/{tid}", f"/targets/{tid}/authorizations"):
        assert world.request("viewer_b", "GET", f"{API}{path}").status_code == 404


def test_membership_removal_does_not_cancel_authorized_work(world: World) -> None:
    """Authorization happens when work is requested; the worker revalidates
    the target authorization on its own and never looks at memberships."""
    user = world.live.user(unique("runner"))
    world.add_member("a", user.id, ProjectRole.OPERATOR)
    token = login(world.client, user.username).json()["token"]
    target = world.ids["a"]["target"]
    aid = world.client.post(
        f"{API}/targets/{target}/assessments", headers=bearer(token), json={"name": unique()}
    ).json()["id"]
    assert (
        world.client.post(f"{API}/assessments/{aid}/start", headers=bearer(token)).status_code
        == 200
    )
    scan = world.client.post(f"{API}/assessments/{aid}/scans", headers=bearer(token), json={})
    assert scan.status_code == 201, scan.text
    scan_id = uuid.UUID(scan.json()["id"])
    world.set_role("a", user.id, None)
    env = world.env["a"]
    for _ in range(5):
        if env.get_scan(scan_id).status.value != "queued":
            break
        env.worker().run_once()
    assert env.get_scan(scan_id).status.value == "completed"
    assert world.client.get(f"{API}/scans/{scan_id}", headers=bearer(token)).status_code == 404


# --- actor identity ------------------------------------------------------------------------------


def test_actor_is_the_authenticated_user_and_history_is_untouched(world: World) -> None:
    a = world.ids["a"]
    url = f"{API}/findings/{a['finding_2']}/triage"
    resp = world.request(
        "operator_a", "POST", url, {"status": "confirmed", "triaged_by": "Mallory"}
    )
    assert resp.status_code == 200, resp.text
    username = world.users["operator_a"].username
    assert resp.json()["status_changed_by"] == username
    history = world.request("viewer_a", "GET", f"{API}/findings/{a['finding_2']}/history").json()
    assert history[-1]["changed_by"] == username
    # Self-asserted text recorded before (by the workflow) is unchanged.
    authorizations = world.request("viewer_a", "GET", f"{API}/targets/{a['target']}/authorizations")
    assert {r["acknowledged_by"] for r in authorizations.json()} == {"Tester"}


# --- concurrency ---------------------------------------------------------------------------------


def run_threads(*targets: Callable[[], None]) -> None:
    errors: list[BaseException] = []

    def wrap(fn: Callable[[], None]) -> Callable[[], None]:
        def run() -> None:
            try:
                fn()
            except BaseException as exc:  # re-raised in the main thread
                errors.append(exc)

        return run

    threads = [threading.Thread(target=wrap(t), daemon=True) for t in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert not errors, errors


def test_membership_removal_while_requests_execute(world: World) -> None:
    user = world.live.user(unique("reader"))
    world.add_member("a", user.id, ProjectRole.VIEWER)
    token = login(world.client, user.username).json()["token"]
    path = f"{API}/targets/{world.ids['a']['target']}"
    removed = threading.Event()
    stop = threading.Event()
    seen: list[tuple[bool, int]] = []
    lock = threading.Lock()

    def reader() -> None:
        client = world.live.client()
        while not stop.is_set():
            after = removed.is_set()
            status = client.get(path, headers=bearer(token)).status_code
            with lock:
                seen.append((after, status))

    def wait_until(condition: Callable[[], bool]) -> None:
        deadline = time.monotonic() + 60
        while not condition() and time.monotonic() < deadline:
            time.sleep(0.01)

    def writer() -> None:
        try:
            wait_until(lambda: len(seen) >= 20)
            world.set_role("a", user.id, None)
            removed.set()
            wait_until(lambda: sum(1 for after, _ in seen if after) >= 20)
        finally:
            stop.set()

    run_threads(reader, reader, writer)
    assert {status for _, status in seen} <= {200, 404}
    assert all(status == 404 for after, status in seen if after)  # never a stale grant
    assert any(status == 200 for after, status in seen if not after)


def test_owner_transfer_and_concurrent_removal_keep_an_owner(world: World) -> None:
    first, second, third = (world.live.user(unique("owner")) for _ in range(3))
    token = login(world.client, first.username).json()["token"]
    project = world.client.post(
        f"{API}/projects", headers=bearer(token), json={"name": unique()}
    ).json()["id"]
    world.created_projects.append(uuid.UUID(project))
    engine = world.live.engine
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO project_members (project_id, user_id, role) VALUES (:p, :u, 'owner')"
            ),
            {"p": project, "u": second.id},
        )
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def remove(user_id: uuid.UUID) -> Callable[[], None]:
        def run() -> None:
            with engine.connect() as conn:
                tx = conn.begin()
                conn.execute(
                    text("DELETE FROM project_members WHERE project_id = :p AND user_id = :u"),
                    {"p": project, "u": user_id},
                )
                barrier.wait()
                try:
                    tx.commit()
                    outcomes.append("committed")
                except Exception as exc:
                    assert "at least one owner" in str(exc)
                    outcomes.append("refused")

        return run

    run_threads(remove(first.id), remove(second.id))
    assert sorted(outcomes) == ["committed", "refused"]
    # Transfer within one transaction: add the new owner, remove the old one.
    with engine.begin() as conn:
        (remaining,) = conn.execute(
            text("SELECT user_id FROM project_members WHERE project_id = :p"), {"p": project}
        ).one()
        conn.execute(
            text(
                "INSERT INTO project_members (project_id, user_id, role) VALUES (:p, :u, 'owner')"
            ),
            {"p": project, "u": third.id},
        )
        conn.execute(
            text("DELETE FROM project_members WHERE project_id = :p AND user_id = :u"),
            {"p": project, "u": remaining},
        )
    third_token = login(world.client, third.username).json()["token"]
    assert (
        world.client.get(f"{API}/projects/{project}", headers=bearer(third_token)).status_code
        == 200
    )
    assert world.client.get(f"{API}/projects/{project}", headers=bearer(token)).status_code == 404


def test_scan_creation_races_target_reauthorization(world: World) -> None:
    """Phase 3 lock order (assessment, then target) stays authoritative: a
    scan created while the owner re-authorizes the target either sees the old
    or the new authorization, never a deadlock or an error."""
    project = world.ids["a"]["project"]
    tid = world.request(
        "owner_a", "POST", f"{API}/projects/{project}/targets", target_body(world)
    ).json()["id"]
    for _ in range(3):
        aid = world.request(
            "operator_a", "POST", f"{API}/targets/{tid}/assessments", {"name": unique()}
        ).json()["id"]
        assert (
            world.request("operator_a", "POST", f"{API}/assessments/{aid}/start").status_code == 200
        )
        barrier = threading.Barrier(2)
        results: dict[str, Any] = {}

        def scan(
            aid: str = aid, barrier: threading.Barrier = barrier, results: dict[str, Any] = results
        ) -> None:
            barrier.wait()
            results["scan"] = world.live.client().post(
                f"{API}/assessments/{aid}/scans",
                headers=bearer(world.tokens["operator_a"]),
                json={},
            )

        def reauthorize(
            aid: str = aid, barrier: threading.Barrier = barrier, results: dict[str, Any] = results
        ) -> None:
            barrier.wait()
            results["patch"] = world.live.client().patch(
                f"{API}/targets/{tid}",
                headers=bearer(world.tokens["owner_a"]),
                json={"authorization": target_body(world)["authorization"]},
            )

        run_threads(scan, reauthorize)
        assert results["patch"].status_code == 200, results["patch"].text
        assert results["scan"].status_code in (201, 409), results["scan"].text
        if results["scan"].status_code == 201:
            with world.live.engine.connect() as conn:
                owner = conn.scalar(
                    text(
                        "SELECT ta.target_id FROM scans s JOIN "
                        "target_authorizations ta ON ta.id = s.authorization_id "
                        "WHERE s.id = :s"
                    ),
                    {"s": results["scan"].json()["id"]},
                )
            assert str(owner) == tid
            world.request(
                "operator_a", "POST", f"{API}/scans/{results['scan'].json()['id']}/cancel"
            )


def test_assessment_deletion_races_scan_creation(world: World) -> None:
    project = world.ids["a"]["project"]
    tid = world.request(
        "owner_a", "POST", f"{API}/projects/{project}/targets", target_body(world)
    ).json()["id"]
    for start in (False, True):
        aid = world.request(
            "operator_a", "POST", f"{API}/targets/{tid}/assessments", {"name": unique()}
        ).json()["id"]
        if start:
            assert (
                world.request("operator_a", "POST", f"{API}/assessments/{aid}/start").status_code
                == 200
            )
        barrier = threading.Barrier(2)
        results: dict[str, int] = {}

        def delete(
            aid: str = aid, barrier: threading.Barrier = barrier, results: dict[str, Any] = results
        ) -> None:
            barrier.wait()
            results["delete"] = (
                world.live.client()
                .delete(f"{API}/assessments/{aid}", headers=bearer(world.tokens["owner_a"]))
                .status_code
            )

        def scan(
            aid: str = aid, barrier: threading.Barrier = barrier, results: dict[str, Any] = results
        ) -> None:
            barrier.wait()
            results["scan"] = (
                world.live.client()
                .post(
                    f"{API}/assessments/{aid}/scans",
                    headers=bearer(world.tokens["operator_a"]),
                    json={},
                )
                .status_code
            )

        run_threads(delete, scan)
        if start:  # an in-progress assessment cannot be deleted; the scan is created
            assert results == {"delete": 409, "scan": 201}
        else:  # a planned one is deleted; a scan is refused (not started) or not found
            assert results["delete"] == 204 and results["scan"] in (404, 409)
        with world.live.engine.connect() as conn:
            assert (
                conn.scalar(
                    text(
                        "SELECT count(*) FROM scans s LEFT JOIN assessments a ON "
                        "a.id = s.assessment_id WHERE a.id IS NULL"
                    )
                )
                == 0
            )
            assert (
                conn.scalar(
                    text(
                        "SELECT count(*) FROM scans s JOIN assessments a ON a.id = "
                        "s.assessment_id WHERE s.target_id <> a.target_id"
                    )
                )
                == 0
            )


def test_role_change_while_requests_execute(world: World) -> None:
    user = world.live.user(unique("flipper"))
    world.add_member("a", user.id, ProjectRole.OPERATOR)
    token = login(world.client, user.username).json()["token"]
    path = f"{API}/assessments/{world.ids['a']['assessment']}/start"  # completed: 409 if allowed
    stop = threading.Event()
    seen: list[int] = []

    def requester() -> None:
        client = world.live.client()
        while not stop.is_set():
            seen.append(client.post(path, headers=bearer(token)).status_code)

    def flipper() -> None:
        try:
            for i in range(20):
                role = ProjectRole.VIEWER if i % 2 == 0 else ProjectRole.OPERATOR
                world.set_role("a", user.id, role)
            world.set_role("a", user.id, ProjectRole.VIEWER)
        finally:
            stop.set()

    run_threads(requester, requester, flipper)
    assert seen and set(seen) <= {403, 409}
    assert world.client.post(path, headers=bearer(token)).status_code == 403
