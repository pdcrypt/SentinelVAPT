"""Phase 9 M5: trusted, server-owned actor identity, through real sessions
against the M4 two-project world.

Every persisted human actor is the authenticated user (Principal.user_id);
request bodies, headers and usernames never select one; workers record
themselves (claimed_by) and never stand in for the requester; actor columns
are immutable and point at users that cannot be deleted."""

import json
import threading
import uuid
from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.models import User, UserCredential
from app.models.enums import ProjectRole
from app.services.audit import AuditContext
from app.services.auth import AuthService
from app.worker import WorkerRole
from tests.integration.auth_support import PASSWORD, bearer, login
from tests.integration.m4_support import World, world
from tests.integration.test_m4_enforcement import run_threads, target_body, unique

pytestmark = pytest.mark.integration

__all__ = ["world"]

API = "/api/v1"
ACTOR_TABLES = [
    ("target_authorizations", "acknowledged_by_user_id"),
    ("assessments", "created_by_user_id"),
    ("scans", "requested_by_user_id"),
    ("finding_status_changes", "changed_by_user_id"),
    ("reports", "requested_by_user_id"),
    ("retest_reports", "requested_by_user_id"),
    ("findings", "status_changed_by_user_id"),
]
REPORT = {"kind": "draft", "title": "M5", "formats": ["json"]}


def scalar(w: World, sql: str, **params: Any) -> Any:
    with w.live.engine.connect() as conn:
        return conn.execute(text(sql), params).scalar()


def user_id(w: World, name: str) -> str:
    return str(w.users[name].id)


def fresh_member(w: World, role: ProjectRole, side: str = "a") -> tuple[Any, str]:
    """A new user who is a member of project A (or B), with a session."""
    user = w.live.user(unique("m5"))
    w.add_member(side, user.id, role)
    return user, login(w.client, user.username).json()["token"]


def as_token(w: World, token: str, method: str, path: str, body: Any = None, **kw: Any) -> Any:
    headers = {**bearer(token), **kw.pop("headers", {})}
    if body is None:
        return w.client.request(method, f"{API}{path}", headers=headers, **kw)
    return w.client.request(method, f"{API}{path}", headers=headers, json=body, **kw)


def running_assessment(w: World, actor: str = "operator_a") -> str:
    """A new started assessment on project A's lab target (scan-ready)."""
    target = w.ids["a"]["target"]
    aid: str = w.request(
        actor, "POST", f"{API}/targets/{target}/assessments", {"name": unique()}
    ).json()["id"]
    assert w.request(actor, "POST", f"{API}/assessments/{aid}/start").status_code == 200
    return aid


# --- the authenticated user is the actor --------------------------------------------------------


def test_each_user_is_recorded_as_themselves(world: World) -> None:
    """Different users performing the same operations are each recorded,
    by user id, with their display name as the descriptive label."""
    w, a = world, world.ids["a"]
    project = a["project"]
    for actor in ("owner_a",):
        target = w.request(actor, "POST", f"{API}/projects/{project}/targets", target_body(w))
        assert target.status_code == 201, target.text
        auth = target.json()["authorization"]
        assert auth["acknowledged_by_user_id"] == user_id(w, actor)
        assert auth["acknowledged_by"] == w.users[actor].display_name
        stored = scalar(
            w,
            "SELECT acknowledged_by_user_id FROM target_authorizations WHERE id = :i",
            i=auth["id"],
        )
        assert str(stored) == user_id(w, actor)
    for actor in ("owner_a", "operator_a"):
        created = w.request(
            actor, "POST", f"{API}/targets/{a['target']}/assessments", {"name": unique()}
        ).json()
        assert created["created_by_user_id"] == user_id(w, actor)
        assert str(
            scalar(w, "SELECT created_by_user_id FROM assessments WHERE id = :i", i=created["id"])
        ) == user_id(w, actor)
    aid = running_assessment(w, "owner_a")
    scan = w.request("operator_a", "POST", f"{API}/assessments/{aid}/scans", {}).json()
    assert scan["requested_by_user_id"] == user_id(w, "operator_a")  # not the assessment's creator
    w.request("operator_a", "POST", f"{API}/scans/{scan['id']}/cancel")


def test_report_and_retest_provenance_is_server_derived(world: World) -> None:
    w, a = world, world.ids["a"]
    report = w.request(
        "operator_a",
        "POST",
        f"{API}/assessments/{a['assessment']}/reports",
        {**REPORT, "scan_id": a["scan"]},
    )
    assert report.status_code == 202, report.text
    body = report.json()
    operator = w.users["operator_a"]
    assert body["requested_by_user_id"] == str(operator.id)
    assert body["prepared_by"] == operator.display_name
    snapshot = scalar(w, "SELECT snapshot FROM reports WHERE id = :i", i=body["id"])
    assert snapshot["document"]["prepared_by"] == operator.display_name
    retest = w.request(
        "owner_a", "POST", f"{API}/assessments/{a['retest_c']}/retests", {"name": unique()}
    )
    assert retest.status_code == 201, retest.text
    assert retest.json()["created_by_user_id"] == user_id(w, "owner_a")
    rr = w.request(
        "viewer_a",
        "POST",
        f"{API}/assessments/{a['retest']}/comparisons/{a['comparison']}/reports",
        {"title": "M5", "formats": ["json"]},
    )
    assert rr.status_code == 403  # M4 unchanged: viewers cannot request reports
    rr = w.request(
        "operator_a",
        "POST",
        f"{API}/assessments/{a['retest']}/comparisons/{a['comparison']}/reports",
        {"title": unique(), "formats": ["json"]},
    )
    assert rr.status_code == 202, rr.text
    assert rr.json()["requested_by_user_id"] == str(operator.id)
    assert rr.json()["prepared_by"] == operator.display_name


def test_triage_actor_is_server_derived(world: World) -> None:
    w, a = world, world.ids["a"]
    url = f"{API}/findings/{a['finding_2']}/triage"
    for actor, status in (("operator_a", "accepted_risk"), ("owner_a", "open")):
        body = {"status": status, "reason": "m5"} if status != "open" else {"status": status}
        resp = w.request(actor, "POST", url, body)
        assert resp.status_code == 200, resp.text
        assert resp.json()["status_changed_by_user_id"] == user_id(w, actor)
    history = w.request("viewer_a", "GET", f"{API}/findings/{a['finding_2']}/history").json()
    recorded = {(h["to_status"], h["changed_by_user_id"]) for h in history}
    assert {
        ("accepted_risk", user_id(w, "operator_a")),
        ("open", user_id(w, "owner_a")),
    } <= recorded


# --- client input never selects an actor --------------------------------------------------------


def spoof_values(w: World) -> list[Any]:
    """Another member, an admin, a nonexistent user, a username, the system
    actor, null and empty."""
    return [
        user_id(w, "owner_b"),
        user_id(w, "admin"),
        str(uuid.uuid4()),
        w.users["owner_b"].username,
        "system:worker",
        None,
        "",
    ]


SPOOF_FIELDS = [
    "actor",
    "actor_id",
    "user_id",
    "created_by",
    "created_by_user_id",
    "requested_by",
    "requested_by_user_id",
    "prepared_by",
    "acknowledged_by",
    "acknowledged_by_user_id",
    "triaged_by",
    "changed_by_user_id",
    "performed_by",
]


def operations(w: World) -> list[tuple[str, str, str, Callable[[], dict[str, Any]]]]:
    """(actor, method, path, valid body) for every request that records an actor."""
    a = w.ids["a"]
    return [
        ("owner_a", "POST", f"/projects/{a['project']}/targets", lambda: target_body(w)),
        (
            "owner_a",
            "PATCH",
            f"/targets/{a['target']}",
            lambda: {"authorization": target_body(w)["authorization"]},
        ),
        ("operator_a", "POST", f"/targets/{a['target']}/assessments", lambda: {"name": unique()}),
        ("operator_a", "POST", f"/assessments/{a['assessment']}/scans", lambda: {}),
        ("operator_a", "POST", f"/findings/{a['finding']}/triage", lambda: {"status": "confirmed"}),
        (
            "operator_a",
            "POST",
            f"/assessments/{a['assessment']}/reports",
            lambda: {**REPORT, "scan_id": a["scan"]},
        ),
        ("operator_a", "POST", f"/assessments/{a['retest_c']}/retests", lambda: {"name": unique()}),
        (
            "operator_a",
            "POST",
            f"/assessments/{a['retest']}/comparisons/{a['comparison']}/reports",
            lambda: {"title": unique(), "formats": ["json"]},
        ),
        ("owner_a", "POST", "/projects", lambda: {"name": unique()}),
    ]


def actor_rows(w: World) -> int:
    return sum(scalar(w, f"SELECT count(*) FROM {table}") for table, _ in ACTOR_TABLES[:6])  # noqa: S608


def test_actor_fields_in_request_bodies_are_refused(world: World) -> None:
    """Any field naming an actor, with any value (another member, an admin,
    a nonexistent id, a username, the system actor, null, empty), top-level
    or nested, is refused with 422 and records nothing."""
    w = world
    before = actor_rows(w)
    for actor, method, path, body in operations(w):
        for field in SPOOF_FIELDS:
            for value in [*spoof_values(w)[:3], "system:worker", None]:
                resp = w.request(actor, method, f"{API}{path}", {**body(), field: value})
                assert resp.status_code == 422, (path, field, value, resp.text)
                assert any(e["type"] == "extra_forbidden" for e in resp.json()["detail"])
    for field in SPOOF_FIELDS:
        for value in spoof_values(w):
            nested = {**target_body(w)}
            nested["authorization"] = {**nested["authorization"], field: value}
            for method, path in (
                ("POST", f"/projects/{w.ids['a']['project']}/targets"),
                ("PATCH", f"/targets/{w.ids['a']['target']}"),
            ):
                payload = nested if method == "POST" else {"authorization": nested["authorization"]}
                resp = w.request("owner_a", method, f"{API}{path}", payload)
                assert resp.status_code == 422, (method, field, value)
    assert actor_rows(w) == before


def test_users_with_the_same_name_are_told_apart(world: World) -> None:
    """Display names (and usernames) are labels: two users with the same
    display name are recorded as two different user ids."""
    w, a = world, world.ids["a"]
    tokens, users = [], []
    for _ in range(2):
        with w.live.factory() as s:
            user = User(username=f"m2-twin-{uuid.uuid4().hex[:8]}", display_name="Same Name")
            s.add(user)
            s.flush()
            s.add(UserCredential(user_id=user.id, password_hash=w.live.passwords.hash(PASSWORD)))
            s.commit()
            s.refresh(user)
        w.add_member("a", user.id, ProjectRole.OPERATOR)
        users.append(user)
        tokens.append(login(w.client, user.username).json()["token"])
    for user, token in zip(users, tokens, strict=True):
        created = as_token(
            w, token, "POST", f"/targets/{a['target']}/assessments", {"name": unique()}
        ).json()
        assert created["created_by_user_id"] == str(user.id)
        triaged = as_token(
            w,
            token,
            "POST",
            f"/findings/{a['finding_2']}/triage",
            {"status": "accepted_risk", "reason": f"twin {user.id}"},
        )
        assert triaged.status_code == 200, triaged.text
        assert triaged.json()["status_changed_by_user_id"] == str(user.id)
        assert triaged.json()["status_changed_by"] == "Same Name"
        as_token(w, token, "POST", f"/findings/{a['finding_2']}/triage", {"status": "open"})


def test_duplicate_actor_keys_are_refused(world: World) -> None:
    raw = (
        '{"status": "confirmed", "triaged_by": "'
        + user_id(world, "owner_b")
        + '", "triaged_by": "'
        + user_id(world, "admin")
        + '"}'
    )
    resp = world.client.post(
        f"{API}/findings/{world.ids['a']['finding']}/triage",
        content=raw,
        headers={**bearer(world.tokens["operator_a"]), "Content-Type": "application/json"},
    )
    assert resp.status_code == 422


@pytest.mark.parametrize(
    "header", ["X-User", "X-Actor", "X-Username", "X-User-Id", "X-Forwarded-User", "X-Remote-User"]
)
def test_identity_headers_are_ignored(world: World, header: str) -> None:
    w = world
    for value in (user_id(w, "owner_b"), user_id(w, "admin"), w.users["admin"].username):
        resp = w.request(
            "operator_a",
            "POST",
            f"{API}/targets/{w.ids['a']['target']}/assessments",
            {"name": unique()},
            headers={header: value},
        )
        assert resp.status_code == 201
        assert resp.json()["created_by_user_id"] == user_id(w, "operator_a")
    # Without a session, no header authenticates anyone.
    resp = w.client.post(
        f"{API}/targets/{w.ids['a']['target']}/assessments",
        json={"name": unique()},
        headers={header: user_id(w, "owner_a")},
    )
    assert resp.status_code == 401


def test_actor_input_never_changes_authorization(world: World) -> None:
    """Project A's owner naming project B's owner as actor: still M4's 404;
    a viewer naming the owner: still 403; nothing is recorded."""
    w, b = world, world.ids["b"]
    before = actor_rows(w)
    for headers in ({}, {"X-User-Id": user_id(w, "owner_b")}):
        resp = w.request(
            "owner_a",
            "POST",
            f"{API}/targets/{b['target']}/assessments",
            {"name": unique()},
            headers=headers,
        )
        assert resp.status_code == 404
    spoofed = w.request(
        "owner_a",
        "POST",
        f"{API}/targets/{b['target']}/assessments",
        {"name": unique(), "created_by_user_id": user_id(w, "owner_b")},
    )
    assert spoofed.status_code == 404  # authorization runs before body validation
    viewer = w.request(
        "viewer_a",
        "POST",
        f"{API}/findings/{w.ids['a']['finding']}/triage",
        {"status": "confirmed", "triaged_by": user_id(w, "owner_a")},
    )
    assert viewer.status_code == 403
    operator = w.request(
        "operator_a",
        "PATCH",
        f"{API}/targets/{w.ids['a']['target']}",
        {"authorization": target_body(w)["authorization"]},
    )
    assert operator.status_code == 403  # target authorization stays owner-only
    assert actor_rows(w) == before


# --- workers and the system actor ---------------------------------------------------------------


def test_workers_record_themselves_and_never_impersonate_the_requester(world: World) -> None:
    w = world
    aid = running_assessment(w)
    scan = w.request("operator_a", "POST", f"{API}/assessments/{aid}/scans", {}).json()
    env = w.env["a"]
    scan_id = uuid.UUID(scan["id"])
    worker = env.worker("m5-worker", role=WorkerRole.SCANS)
    claimed = worker.claim()
    assert claimed is not None and claimed.scan_id == scan_id
    worker.execute(claimed)
    assert worker.analyze_once()
    stored = env.get_scan(scan_id)
    assert stored.status.value == "completed"
    assert stored.claimed_by == "m5-worker"  # the performer: the worker itself
    assert str(stored.requested_by_user_id) == user_id(w, "operator_a")  # the requester, unchanged
    report = w.request(
        "operator_a",
        "POST",
        f"{API}/assessments/{aid}/reports",
        {**REPORT, "scan_id": str(scan_id)},
    )
    assert report.status_code == 202, report.text
    rid = report.json()["id"]
    reports = env.worker("m5-reports", role=WorkerRole.REPORTS)
    for _ in range(20):  # earlier tests may have queued reports too
        if scalar(w, "SELECT status FROM reports WHERE id = :i", i=rid) == "completed":
            break
        assert reports.run_once()
    row = w.live.rows(
        "SELECT claimed_by, requested_by_user_id, prepared_by FROM reports WHERE id = :i", i=rid
    )[0]
    assert row.claimed_by == "m5-reports"
    assert str(row.requested_by_user_id) == user_id(w, "operator_a")
    assert row.prepared_by == w.users["operator_a"].display_name
    # No worker or user ever appears as another's requester: users only.
    for table, column in ACTOR_TABLES:
        unknown = scalar(
            w,
            f"SELECT count(*) FROM {table} x WHERE {column} IS NOT NULL "  # noqa: S608
            f"AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = x.{column})",
        )
        assert unknown == 0, table


def test_actor_columns_are_written_once(world: World) -> None:
    """The database refuses a row without its actor and any later change of
    it, whoever asks (a worker included)."""
    w, a = world, world.ids["a"]
    other = w.users["owner_b"].id
    rows = {
        "target_authorizations": scalar(
            w, "SELECT id FROM target_authorizations WHERE target_id = :t LIMIT 1", t=a["target"]
        ),
        "assessments": a["assessment"],
        "scans": a["scan"],
        "reports": a["report"],
        "retest_reports": a["retest_report"],
        "finding_status_changes": scalar(
            w, "SELECT id FROM finding_status_changes WHERE changed_by_user_id IS NOT NULL LIMIT 1"
        ),
    }
    for table, column in ACTOR_TABLES[:6]:
        for value in (other, None):
            with pytest.raises(DBAPIError, match="immutable"), w.live.engine.begin() as conn:
                conn.execute(
                    text(f"UPDATE {table} SET {column} = :v WHERE id = :i"),  # noqa: S608
                    {"v": value, "i": rows[table]},
                )
    with pytest.raises(DBAPIError, match="must name the user"), w.live.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO assessments (id, target_id, authorization_id, name) SELECT "
                "gen_random_uuid(), target_id, authorization_id, 'no actor' FROM assessments "
                "WHERE id = :a"
            ),
            {"a": a["assessment"]},
        )
    with pytest.raises(DBAPIError, match="must name the user"), w.live.engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE findings SET status = 'confirmed', status_changed_at = now(), "
                "status_changed_by_user_id = NULL WHERE id = :f"
            ),
            {"f": a["finding"]},
        )


def test_users_cannot_be_deleted_to_erase_provenance(world: World) -> None:
    w = world
    actor = w.users["operator_a"].id
    with pytest.raises(DBAPIError), w.live.engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE id = :u"), {"u": actor})
    rules = w.live.rows(
        "SELECT conrelid::regclass::text AS tbl, confdeltype FROM pg_constraint "
        "WHERE contype = 'f' AND confrelid = 'users'::regclass "
        "AND conname LIKE 'fk_%_user_id_users'"
    )
    by_table = {r.tbl: r.confdeltype for r in rules}
    for table, _ in ACTOR_TABLES:
        assert by_table.get(table) == "r", table  # ON DELETE RESTRICT


def test_disabled_users_remain_valid_historical_actors(world: World) -> None:
    w, a = world, world.ids["a"]
    user, token = fresh_member(w, ProjectRole.OPERATOR)
    created = as_token(
        w, token, "POST", f"/targets/{a['target']}/assessments", {"name": unique()}
    ).json()
    with w.live.factory() as s:
        AuthService(s, w.live.settings, w.live.clock, w.live.passwords).disable_user(
            user.id, AuditContext(request_id=None, source="m5-test"), actor="m5-test"
        )
    assert as_token(w, token, "GET", f"/assessments/{created['id']}").status_code == 401
    shown = w.request("viewer_a", "GET", f"{API}/assessments/{created['id']}").json()
    assert shown["created_by_user_id"] == str(user.id)
    assert scalar(w, "SELECT is_active FROM users WHERE id = :u", u=user.id) is False


# --- authentication actors ------------------------------------------------------------------------


def test_password_change_and_logout_actors_cannot_be_spoofed(world: World) -> None:
    w = world
    user, token = fresh_member(w, ProjectRole.VIEWER)
    victim_token = login(w.client, w.users["viewer_a"].username).json()["token"]
    victim = str(w.users["viewer_a"].id)
    for extra in (
        {"user_id": victim},
        {"username": w.users["viewer_a"].username},
        {"actor_id": victim},
    ):
        resp = as_token(
            w,
            token,
            "POST",
            "/auth/password",
            {"current_password": PASSWORD, "new_password": "another-lab-pass-9876", **extra},
        )
        assert resp.status_code == 422, extra
    changed = as_token(
        w,
        token,
        "POST",
        "/auth/password",
        {"current_password": PASSWORD, "new_password": "another-lab-pass-9876"},
        headers={"X-User-Id": victim},
    )
    assert changed.status_code == 200
    token = changed.json()["token"]
    events = w.live.rows(
        "SELECT actor_user_id FROM audit_events WHERE action = 'auth.password_changed'"
        " AND actor_user_id IN (:a, :b)",
        a=user.id,
        b=w.users["viewer_a"].id,
    )
    assert [e.actor_user_id for e in events] == [user.id]
    # Logout ends the caller's own session, whatever the request names.
    out = w.client.post(
        f"{API}/auth/logout",
        headers={**bearer(token), "X-User-Id": victim},
        content=json.dumps({"user_id": victim, "session_id": "x"}),
    )
    assert out.status_code == 204
    assert as_token(w, token, "GET", "/auth/me").status_code == 401
    assert as_token(w, victim_token, "GET", "/auth/me").json()["user"]["id"] == victim


# --- concurrency ---------------------------------------------------------------------------------


def test_concurrent_requests_never_share_an_actor(world: World) -> None:
    """Two users, and one user many times, creating assessments at once:
    every row names exactly the user whose session made it."""
    w, a = world, world.ids["a"]
    tokens = {name: w.tokens[name] for name in ("owner_a", "operator_a")}
    results: list[tuple[str, str]] = []
    lock = threading.Lock()

    def worker(name: str) -> Callable[[], None]:
        def run() -> None:
            client = w.live.client()
            for _ in range(4):
                resp = client.post(
                    f"{API}/targets/{a['target']}/assessments",
                    headers=bearer(tokens[name]),
                    json={"name": unique()},
                )
                assert resp.status_code == 201, resp.text
                with lock:
                    results.append((name, resp.json()["id"]))

        return run

    run_threads(worker("owner_a"), worker("operator_a"), worker("operator_a"))
    assert len(results) == 12
    for name, aid in results:
        assert str(
            scalar(w, "SELECT created_by_user_id FROM assessments WHERE id = :i", i=aid)
        ) == user_id(w, name)


def test_concurrent_triage_records_each_user(world: World) -> None:
    w, a = world, world.ids["a"]
    other, other_token = fresh_member(w, ProjectRole.OPERATOR)
    fid = scalar(
        w,
        "SELECT id FROM findings WHERE scan_id = :s AND status = 'open' "
        "AND id NOT IN (:f1, :f2) LIMIT 1",
        s=a["scan"],
        f1=a["finding"],
        f2=a["finding_2"],
    )
    barrier = threading.Barrier(2)
    statuses: dict[str, int] = {}

    def triage(name: str, token: str, status: str) -> Callable[[], None]:
        def run() -> None:
            client = w.live.client()
            barrier.wait()
            body = {"status": status, "reason": "m5 race"}
            statuses[name] = client.post(
                f"{API}/findings/{fid}/triage", headers=bearer(token), json=body
            ).status_code

        return run

    run_threads(
        triage("operator_a", w.tokens["operator_a"], "accepted_risk"),
        triage("other", other_token, "false_positive"),
    )
    assert sorted(statuses.values()) == [200, 200]  # serialized on the finding's row lock
    history = w.live.rows(
        "SELECT to_status, changed_by_user_id FROM finding_status_changes "
        "WHERE finding_id = :f ORDER BY changed_at, id",
        f=fid,
    )
    expected = {"accepted_risk": w.users["operator_a"].id, "false_positive": other.id}
    assert {h.to_status: h.changed_by_user_id for h in history} == expected
    last = w.live.rows(
        "SELECT status, status_changed_by_user_id FROM findings WHERE id = :f", f=fid
    )[0]
    assert last.status_changed_by_user_id == expected[last.status]


def test_concurrent_target_reauthorization_records_each_owner(world: World) -> None:
    w, a = world, world.ids["a"]
    second, second_token = fresh_member(w, ProjectRole.OWNER)
    target = w.request(
        "owner_a", "POST", f"{API}/projects/{a['project']}/targets", target_body(w)
    ).json()["id"]
    barrier = threading.Barrier(2)
    refs: dict[str, str] = {}

    def reauthorize(name: str, token: str) -> Callable[[], None]:
        def run() -> None:
            client = w.live.client()
            reference = unique("ref")
            refs[reference] = name
            body = {"authorization": {**target_body(w)["authorization"], "reference": reference}}
            barrier.wait()
            resp = client.patch(f"{API}/targets/{target}", headers=bearer(token), json=body)
            assert resp.status_code == 200, resp.text

        return run

    run_threads(reauthorize("owner_a", w.tokens["owner_a"]), reauthorize("second", second_token))
    rows = w.live.rows(
        "SELECT version, reference, acknowledged_by_user_id FROM "
        "target_authorizations WHERE target_id = :t ORDER BY version",
        t=target,
    )
    assert [r.version for r in rows] == [1, 2, 3]
    ids = {"owner_a": w.users["owner_a"].id, "second": second.id}
    for row in rows[1:]:
        assert row.acknowledged_by_user_id == ids[refs[row.reference]]


def test_concurrent_report_requests_record_each_requester(world: World) -> None:
    w, a = world, world.ids["a"]
    barrier = threading.Barrier(2)
    created: dict[str, str] = {}

    def request(name: str) -> Callable[[], None]:
        def run() -> None:
            client = w.live.client()
            barrier.wait()
            resp = client.post(
                f"{API}/assessments/{a['assessment']}/reports",
                headers=bearer(w.tokens[name]),
                json={**REPORT, "scan_id": a["scan"]},
            )
            assert resp.status_code == 202, resp.text
            created[name] = resp.json()["id"]

        return run

    run_threads(request("owner_a"), request("operator_a"))
    for name, rid in created.items():
        assert str(
            scalar(w, "SELECT requested_by_user_id FROM reports WHERE id = :i", i=rid)
        ) == user_id(w, name)


def test_disablement_and_membership_changes_during_requests(world: World) -> None:
    """A user disabled, or removed from the project, while their requests
    run: each request either completes as that user or is refused; none is
    ever recorded as anyone else."""
    w, a = world, world.ids["a"]
    for change in ("disable", "remove"):
        user, token = fresh_member(w, ProjectRole.OPERATOR)
        outcomes: list[tuple[int, str | None]] = []
        started = threading.Event()

        def requester(token: str = token, out: list[Any] = outcomes, ev: Any = started) -> None:
            client = w.live.client()
            for i in range(15):
                resp = client.post(
                    f"{API}/targets/{a['target']}/assessments",
                    headers=bearer(token),
                    json={"name": unique()},
                )
                out.append(
                    (resp.status_code, resp.json().get("id") if resp.status_code == 201 else None)
                )
                if i == 2:
                    ev.set()

        def changer(user: Any = user, change: str = change, ev: Any = started) -> None:
            ev.wait(30)
            if change == "disable":
                with w.live.factory() as s:
                    AuthService(s, w.live.settings, w.live.clock, w.live.passwords).disable_user(
                        user.id, AuditContext(request_id=None, source="m5-test"), actor="m5-test"
                    )
            else:
                w.set_role("a", user.id, None)

        run_threads(requester, changer)
        assert {code for code, _ in outcomes} <= {201, 401, 404}, change
        assert outcomes[-1][0] == (401 if change == "disable" else 404), change
        for code, aid in outcomes:
            if code == 201:
                assert (
                    scalar(w, "SELECT created_by_user_id FROM assessments WHERE id = :i", i=aid)
                    == user.id
                )
