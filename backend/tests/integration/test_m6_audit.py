"""Phase 9 M6: audit logging and audit integrity, through real sessions
against the M4 two-project world.

Every request below carries its own X-Request-ID, so the events it produced
are exactly those with that request_id."""

import json
import threading
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.audit import AuditAction
from app.core.errors import AuthenticationError
from app.models.enums import ProjectRole
from app.services.audit import AuditContext, AuditRecorder, AuditService
from app.services.auth import AuthService
from app.worker import WorkerRole
from tests.integration.auth_support import bearer, login
from tests.integration.m4_support import FORBIDDEN, World, world
from tests.integration.test_m4_enforcement import run_threads, target_body, unique

pytestmark = pytest.mark.integration

__all__ = ["world"]

API = "/api/v1"
A = AuditAction


def call(
    w: World, actor: str | None, method: str, path: str, body: Any = None, **kw: Any
) -> tuple[Any, uuid.UUID]:
    request_id = uuid.uuid4()
    headers = {"X-Request-ID": str(request_id), **kw.pop("headers", {})}
    return w.request(actor, method, f"{API}{path}", body, headers=headers, **kw), request_id


def events(w: World, request_id: uuid.UUID) -> list[Any]:
    return w.live.rows(
        "SELECT * FROM audit_events WHERE request_id = :r ORDER BY occurred_at, id", r=request_id
    )


def session_of(w: World, actor: str) -> uuid.UUID:
    """The session row behind the actor's token."""
    me = w.request(actor, "GET", f"{API}/auth/me").json()
    sid = w.live.scalar(
        "SELECT id FROM sessions WHERE user_id = :u AND revoked_at IS NULL "
        "ORDER BY created_at DESC LIMIT 1",
        u=uuid.UUID(me["user"]["id"]),
    )
    assert sid is not None
    return uuid.UUID(str(sid))


def fresh_member(w: World, role: ProjectRole, side: str = "a") -> tuple[Any, str]:
    user = w.live.user(unique("m6"))
    w.add_member(side, user.id, role)
    return user, login(w.client, user.username).json()["token"]


def as_token(
    w: World, token: str, method: str, path: str, body: Any = None, **kw: Any
) -> tuple[Any, uuid.UUID]:
    request_id = uuid.uuid4()
    headers = {**bearer(token), "X-Request-ID": str(request_id), **kw.pop("headers", {})}
    if body is None:
        return w.client.request(method, f"{API}{path}", headers=headers, **kw), request_id
    return w.client.request(method, f"{API}{path}", headers=headers, json=body, **kw), request_id


def assert_human(
    event: Any,
    w: World,
    actor: str,
    action: AuditAction,
    *,
    project: str | None = "a",
    outcome: str = "success",
) -> None:
    assert event.action == action.value, event.action
    assert event.outcome == outcome
    assert event.actor_type == "user"
    assert event.actor_user_id == w.users[actor].id
    assert event.session_id == session_of(w, actor)
    expected_project = w.project(project) if project else None
    assert event.project_id == expected_project


# --- successful operations -----------------------------------------------------------------------


def test_state_changes_are_audited_with_actor_session_and_project(world: World) -> None:
    w, a = world, world.ids["a"]
    resp, rid = call(w, "owner_a", "POST", f"/projects/{a['project']}/targets", target_body(w))
    assert resp.status_code == 201
    by_action = {e.action: e for e in events(w, rid)}  # one transaction: one timestamp
    assert set(by_action) == {"target.created", "target_authorization.created"}
    created, authorized = by_action["target.created"], by_action["target_authorization.created"]
    assert_human(created, w, "owner_a", A.TARGET_CREATED)
    assert str(created.resource_id) == resp.json()["id"] and created.resource_type == "target"
    assert_human(authorized, w, "owner_a", A.TARGET_AUTHORIZATION_CREATED)
    assert authorized.metadata["version"] == 1
    assert authorized.metadata["target_id"] == resp.json()["id"]
    target = resp.json()["id"]

    steps = [
        (
            "operator_a",
            "POST",
            f"/targets/{target}/assessments",
            {"name": unique()},
            A.ASSESSMENT_CREATED,
        ),
    ]
    resp, rid = call(w, *steps[0][:4])
    (event,) = events(w, rid)
    assert_human(event, w, "operator_a", A.ASSESSMENT_CREATED)
    aid = resp.json()["id"]
    for actor, path, action in (
        ("operator_a", "start", A.ASSESSMENT_STARTED),
        ("operator_a", "cancel", A.ASSESSMENT_CANCELLED),
    ):
        resp, rid = call(w, actor, "POST", f"/assessments/{aid}/{path}")
        assert resp.status_code == 200, resp.text
        (event,) = events(w, rid)
        assert_human(event, w, actor, action)
        assert str(event.resource_id) == aid
    resp, rid = call(w, "owner_a", "DELETE", f"/assessments/{aid}")
    assert resp.status_code == 204
    (event,) = events(w, rid)
    assert_human(event, w, "owner_a", A.ASSESSMENT_DELETED)


def test_triage_scan_report_and_retest_events(world: World) -> None:
    w, a = world, world.ids["a"]
    resp, rid = call(
        w,
        "operator_a",
        "POST",
        f"/findings/{a['finding_2']}/triage",
        {"status": "false_positive", "reason": "m6 lab artefact"},
    )
    assert resp.status_code == 200, resp.text
    (event,) = events(w, rid)
    assert_human(event, w, "operator_a", A.FINDING_TRIAGED)
    assert event.metadata["to_status"] == "false_positive"
    assert "m6 lab artefact" not in json.dumps(event.metadata)  # the reason text is not copied
    call(w, "operator_a", "POST", f"/findings/{a['finding_2']}/triage", {"status": "open"})

    resp, rid = call(
        w,
        "operator_a",
        "POST",
        f"/assessments/{a['assessment']}/reports",
        {"kind": "draft", "title": "M6", "formats": ["json"], "scan_id": a["scan"]},
    )
    assert resp.status_code == 202
    (event,) = events(w, rid)
    assert_human(event, w, "operator_a", A.REPORT_REQUESTED)
    assert event.metadata == {
        "source": event.metadata["source"],
        "kind": "draft",
        "scan_id": a["scan"],
    }  # the source is the client address

    resp, rid = call(
        w, "operator_a", "POST", f"/assessments/{a['retest']}/comparisons", {"scan_id": a["scan_b"]}
    )
    assert resp.status_code == 200  # already computed: still a recorded request
    (event,) = events(w, rid)
    assert_human(event, w, "operator_a", A.COMPARISON_REQUESTED)
    assert event.metadata["created"] is False


def test_failed_operations_record_nothing(world: World) -> None:
    """A refused lifecycle step (409) or invalid body (422) changes nothing and
    records nothing: the event lives in the operation's transaction."""
    w, a = world, world.ids["a"]
    for actor, method, path, body in (
        ("operator_a", "POST", f"/assessments/{a['assessment']}/complete", None),
        ("operator_a", "POST", f"/findings/{a['finding']}/triage", {"status": "open"}),
        ("owner_a", "DELETE", f"/projects/{a['project']}", None),
        ("operator_a", "POST", f"/targets/{a['target']}/assessments", {"name": ""}),
    ):
        resp, rid = call(w, actor, method, path, body)
        assert resp.status_code in (409, 422), resp.text
        assert events(w, rid) == []


def test_an_audit_failure_rolls_the_change_back(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed: if the event cannot be written, the change is not made."""
    w, a = world, world.ids["a"]
    original = AuditRecorder.record

    def failing(self: AuditRecorder, action: Any, *args: Any, **kwargs: Any) -> uuid.UUID:
        if action == A.ASSESSMENT_CREATED:
            raise RuntimeError("audit storage unavailable")
        return original(self, action, *args, **kwargs)

    monkeypatch.setattr(AuditRecorder, "record", failing)
    name = unique("unaudited")
    with pytest.raises(RuntimeError, match="audit storage"):
        call(w, "operator_a", "POST", f"/targets/{a['target']}/assessments", {"name": name})
    assert w.live.scalar("SELECT count(*) FROM assessments WHERE name = :n", n=name) == 0


# --- denials -------------------------------------------------------------------------------------


def test_security_relevant_denials_are_recorded(world: World) -> None:
    w, a, b = world, world.ids["a"], world.ids["b"]
    # A member without the permission (403).
    resp, rid = call(w, "viewer_a", "POST", f"/targets/{a['target']}/assessments", {"name": "x"})
    assert (resp.status_code, resp.json()) == (403, FORBIDDEN)
    (event,) = events(w, rid)
    assert_human(event, w, "viewer_a", A.AUTHZ_DENIED, outcome="denied")
    assert event.metadata["permission"] == "assessment.write"
    assert event.metadata["reason"] == "insufficient_role" and event.metadata["role"] == "viewer"
    assert (event.resource_type, str(event.resource_id)) == ("target", a["target"])
    # A non-member reaching for another project's existing resource (404).
    resp, rid = call(w, "owner_a", "GET", f"/scans/{b['scan']}")
    assert resp.status_code == 404
    (event,) = events(w, rid)
    assert_human(event, w, "owner_a", A.AUTHZ_DENIED, project="b", outcome="denied")
    assert event.metadata["reason"] == "not_member"
    # The global admin is a non-member like anyone else.
    resp, rid = call(w, "admin", "GET", f"/projects/{a['project']}")
    assert resp.status_code == 404
    (event,) = events(w, rid)
    assert_human(event, w, "admin", A.AUTHZ_DENIED, outcome="denied")
    # A missing global permission.
    resp, rid = call(w, "owner_a", "GET", "/audit-events")
    assert resp.status_code == 403
    (event,) = events(w, rid)
    assert_human(event, w, "owner_a", A.AUTHZ_DENIED, project=None, outcome="denied")
    assert event.metadata["permission"] == "audit.read_global"
    # Target authorization stays owner-only, and that refusal is recorded too.
    resp, rid = call(
        w,
        "operator_a",
        "PATCH",
        f"/targets/{a['target']}",
        {"authorization": target_body(w)["authorization"]},
    )
    assert resp.status_code == 403
    assert [e.metadata["permission"] for e in events(w, rid)] == ["target.manage"]


def test_ordinary_misses_are_not_recorded(world: World) -> None:
    """A resource that does not exist, a malformed id, an anonymous call and
    a plain read are not security history."""
    w = world
    for actor, path in (
        ("owner_a", f"/scans/{uuid.uuid4()}"),
        ("owner_a", "/scans/not-a-uuid"),
        (None, f"/scans/{w.ids['a']['scan']}"),
        ("viewer_a", f"/scans/{w.ids['a']['scan']}"),
    ):
        _, rid = call(w, actor, "GET", path)
        assert events(w, rid) == [], path


def test_target_authorization_refusals_are_recorded(world: World) -> None:
    w, a = world, world.ids["a"]
    now = w.live.clock()
    body = target_body(w, authorization={"valid_until": (now + timedelta(minutes=1)).isoformat()})
    target = w.request("owner_a", "POST", f"{API}/projects/{a['project']}/targets", body).json()[
        "id"
    ]
    planned = w.request(
        "operator_a", "POST", f"{API}/targets/{target}/assessments", {"name": unique()}
    ).json()["id"]
    running = w.request(
        "operator_a", "POST", f"{API}/targets/{target}/assessments", {"name": unique()}
    ).json()["id"]
    assert w.request("operator_a", "POST", f"{API}/assessments/{running}/start").status_code == 200
    w.live.advance(minutes=2)
    resp, rid = call(w, "operator_a", "POST", f"/assessments/{running}/scans", {})
    assert resp.status_code == 409
    (event,) = events(w, rid)
    assert_human(event, w, "operator_a", A.SCAN_REQUEST_REFUSED, outcome="denied")
    assert event.metadata["reason"] == "authorization_not_active"
    assert w.live.scalar("SELECT count(*) FROM scans WHERE assessment_id = :a", a=running) == 0
    resp, rid = call(w, "operator_a", "POST", f"/assessments/{planned}/start")
    assert resp.status_code == 409
    (event,) = events(w, rid)
    assert_human(event, w, "operator_a", A.ASSESSMENT_START_REFUSED, outcome="denied")
    assert event.metadata["reason"] == "authorization_expired"


def test_password_gate_and_rejected_sessions_are_recorded(world: World) -> None:
    w = world
    _, rid = call(w, "pending", "GET", f"/projects/{w.ids['a']['project']}")
    (event,) = events(w, rid)
    assert_human(
        event, w, "pending", A.AUTH_PASSWORD_CHANGE_REQUIRED, project=None, outcome="denied"
    )
    # A token kept after logout.
    user, token = fresh_member(w, ProjectRole.VIEWER)
    sid = w.live.scalar("SELECT id FROM sessions WHERE user_id = :u", u=user.id)
    assert as_token(w, token, "POST", "/auth/logout")[0].status_code == 204
    resp, rid = as_token(w, token, "GET", "/auth/me")
    assert resp.status_code == 401
    (event,) = events(w, rid)
    assert (event.action, event.outcome, event.actor_type) == (
        "auth.session_rejected",
        "denied",
        "anonymous",
    )
    assert (event.resource_type, event.resource_id) == ("session", sid)
    assert event.metadata["reason"] == "revoked" and event.actor_user_id is None
    assert event.session_id is None  # never attributed to the presented session
    # Unknown tokens and natural expiry are routine: not recorded.
    resp, rid = as_token(w, "x" * 43, "GET", "/auth/me")
    assert resp.status_code == 401 and events(w, rid) == []


def test_disabled_users_create_no_new_events(world: World) -> None:
    w, a = world, world.ids["a"]
    user, token = fresh_member(w, ProjectRole.OPERATOR)
    with w.live.factory() as s:
        AuthService(s, w.live.settings, w.live.clock, w.live.passwords).disable_user(
            user.id, AuditContext(request_id=None, source="m6-test"), actor="m6-test"
        )
    resp, rid = as_token(
        w, token, "POST", f"/targets/{a['target']}/assessments", {"name": unique()}
    )
    assert resp.status_code == 401
    (event,) = events(w, rid)  # only the rejected session, attributed to no one
    assert event.action == "auth.session_rejected" and event.metadata["reason"] == "user_disabled"
    assert (
        w.live.scalar(
            "SELECT count(*) FROM audit_events WHERE actor_user_id = :u "
            "AND occurred_at > (SELECT disabled_at FROM users WHERE id = :u)",
            u=user.id,
        )
        == 0
    )
    # The service refuses it, and so does the database, whoever inserts.
    with w.live.factory() as s, pytest.raises(AuthenticationError):
        AuditService(s).user(
            A.ASSESSMENT_CREATED, _actor(user), resource=("assessment", uuid.UUID(a["assessment"]))
        )
    with pytest.raises(DBAPIError, match="only name an active user"):
        _insert(w, actor_type="user", actor_user_id=user.id, actor_label="x")


def _actor(user: Any) -> Any:
    from app.core.actors import UserActor

    return UserActor(user.id, user.display_name)


# --- workers -------------------------------------------------------------------------------------


def test_worker_events_name_the_worker_not_the_requester(world: World) -> None:
    w, a = world, world.ids["a"]
    aid = w.request(
        "operator_a", "POST", f"{API}/targets/{a['target']}/assessments", {"name": unique()}
    ).json()["id"]
    assert w.request("operator_a", "POST", f"{API}/assessments/{aid}/start").status_code == 200
    scan = w.request("operator_a", "POST", f"{API}/assessments/{aid}/scans", {}).json()["id"]
    env = w.env["a"]
    worker = env.worker("m6-worker", role=WorkerRole.SCANS)
    claimed = worker.claim()
    assert claimed is not None and str(claimed.scan_id) == scan
    worker.execute(claimed)
    assert worker.analyze_once()
    rows = w.live.rows(
        "SELECT action, actor_type, actor_user_id, actor_label, session_id, "
        "project_id, outcome FROM audit_events WHERE resource_id = :s "
        "ORDER BY occurred_at, id",
        s=uuid.UUID(scan),
    )
    assert [r.action for r in rows] == ["scan.requested", "scan.started", "scan.completed"]
    requested, *worker_rows = rows
    assert requested.actor_user_id == w.users["operator_a"].id
    for row in worker_rows:
        assert (row.actor_type, row.actor_label, row.actor_user_id, row.session_id) == (
            "system",
            "m6-worker",
            None,
            None,
        )
        assert row.project_id == w.project("a")
    analysis = w.live.rows(
        "SELECT action, actor_label, metadata FROM audit_events WHERE "
        "action = 'analysis.completed' AND metadata ->> 'scan_id' = :s",
        s=scan,
    )
    assert [(r.actor_label) for r in analysis] == ["m6-worker"]


# --- integrity -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "assignment",
    [
        "actor_user_id = NULL",
        "actor_type = 'system'",
        "actor_label = 'someone'",
        "occurred_at = now() - interval '1 day'",
        "project_id = gen_random_uuid()",
        "resource_id = gen_random_uuid()",
        "action = 'auth.logout'",
        "outcome = 'success'",
        "metadata = '{}'::jsonb",
        "session_id = NULL",
        "request_id = gen_random_uuid()",
    ],
)
def test_audit_events_cannot_be_changed(world: World, assignment: str) -> None:
    w = world
    event = w.live.scalar(
        "SELECT id FROM audit_events WHERE actor_type = 'user' AND outcome = 'denied' LIMIT 1"
    )
    assert event is not None
    with pytest.raises(DBAPIError, match="append-only"), w.live.engine.begin() as conn:
        conn.execute(text(f"UPDATE audit_events SET {assignment} WHERE id = :e"), {"e": event})  # noqa: S608


def test_audit_events_cannot_be_deleted_or_truncated(world: World) -> None:
    w = world
    for sql in (
        "DELETE FROM audit_events WHERE id = (SELECT id FROM audit_events LIMIT 1)",
        "TRUNCATE audit_events",
        "UPDATE audit_actions SET description = 'x'",
        "DELETE FROM audit_actions WHERE action = 'auth.login'",
    ):
        with pytest.raises(DBAPIError), w.live.engine.begin() as conn:
            conn.execute(text(sql))


def _insert(w: World, **values: Any) -> None:
    base: dict[str, Any] = {
        "id": uuid.uuid4(),
        "actor_type": "system",
        "actor_user_id": None,
        "actor_label": "m6",
        "session_id": None,
        "action": "scan.started",
        "outcome": "success",
    }
    base.update(values)
    with w.live.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_events (id, actor_type, actor_user_id, actor_label, "
                "session_id, action, outcome) VALUES (:id, :actor_type, "
                ":actor_user_id, :actor_label, :session_id, :action, :outcome)"
            ),
            base,
        )


def test_the_database_refuses_forged_events(world: World) -> None:
    w = world
    owner, viewer = w.users["owner_a"], w.users["viewer_a"]
    cases: list[tuple[dict[str, Any], str]] = [
        ({"action": "scan.exfiltrated"}, "fk_audit_events_action_audit_actions"),
        ({"actor_label": None}, "system_actor_named"),
        ({"session_id": session_of(w, "owner_a")}, "session_only_for_users|must belong"),
        (
            {
                "actor_type": "user",
                "actor_user_id": viewer.id,
                "actor_label": "x",
                "session_id": session_of(w, "owner_a"),
            },
            "must belong to its user",
        ),
        (
            {
                "actor_type": "user",
                "actor_user_id": owner.id,
                "actor_label": "x",
                "session_id": uuid.uuid4(),
            },
            "must belong to its user",
        ),
    ]
    for values, match in cases:
        with pytest.raises(DBAPIError, match=match):
            _insert(w, **values)


@pytest.mark.parametrize(
    "metadata",
    [
        {"password": "x"},
        {"session_token": "x"},
        {"authorization_header": "x"},
        {"cookie": "x"},
        {"api_key": "x"},
        {"request_body": "x"},
        {"nested": {"a": 1}},
        {"list": [1]},
        {"long": "x" * 300},
    ],
)
def test_the_database_refuses_unsafe_metadata(world: World, metadata: dict[str, Any]) -> None:
    with pytest.raises(DBAPIError), world.live.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_events (id, actor_type, actor_label, action, outcome, "
                "metadata) VALUES (gen_random_uuid(), 'system', 'm6', 'scan.started', "
                "'success', CAST(:m AS jsonb))"
            ),
            {"m": json.dumps(metadata)},
        )


# --- reading the audit ---------------------------------------------------------------------------


def test_project_audit_is_for_owners_of_that_project_only(world: World) -> None:
    w, a, b = world, world.ids["a"], world.ids["b"]
    path = f"{API}/projects/{a['project']}/audit-events"
    resp = w.request("owner_a", "GET", path, params={"limit": 100})
    assert resp.status_code == 200
    rows = resp.json()
    assert rows and all(r["project_id"] == a["project"] for r in rows)
    assert all("session_id" not in r for r in rows)
    times = [(r["occurred_at"], r["id"]) for r in rows]
    assert times == sorted(times, reverse=True)
    for actor, status in (
        ("operator_a", 403),
        ("viewer_a", 403),
        ("owner_b", 404),
        ("admin", 404),
        (None, 401),
        ("pending", 403),
    ):
        assert w.request(actor, "GET", path).status_code == status, actor
    # No filter widens the scope: B's resources and events are simply absent.
    for params in (
        {"resource_id": b["scan"]},
        {"actor_user_id": str(w.users["owner_b"].id)},
        {"limit": 100, "offset": 0},
    ):
        body = w.request("owner_a", "GET", path, params=params).text
        assert b["project"] not in body and b["scan"] not in body
    for bad in (
        {"limit": 101},
        {"action": "scan.exfiltrated"},
        {"order_by": "actor_label"},
        {"resource_type": "x;drop"},
        {"occurred_from": "2026-01-01T00:00:00"},
    ):
        status = w.request("owner_a", "GET", path, params=bad).status_code
        assert status == (200 if "order_by" in bad else 422), bad  # unknown params are ignored


def test_global_audit_is_for_global_admins(world: World) -> None:
    w, b = world, world.ids["b"]
    resp = w.request(
        "admin", "GET", f"{API}/audit-events", params={"project_id": b["project"], "limit": 100}
    )
    assert resp.status_code == 200
    rows = resp.json()
    assert rows and {r["project_id"] for r in rows} == {b["project"]}
    assert "session_id" in rows[0]
    denied = w.request(
        "admin",
        "GET",
        f"{API}/audit-events",
        params={"action": "authz.denied", "outcome": "denied"},
    ).json()
    assert denied and all(r["action"] == "authz.denied" for r in denied)
    for actor in ("owner_a", "owner_b", "operator_a"):
        assert w.request(actor, "GET", f"{API}/audit-events").status_code == 403
    # There is no way to write through the API.
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert w.request("admin", method, f"{API}/audit-events", {}).status_code == 405


# --- spoofing ------------------------------------------------------------------------------------


def test_events_never_take_identity_from_the_request(world: World) -> None:
    w, a = world, world.ids["a"]
    other = w.users["owner_b"]
    forged = {
        "X-User": str(other.id),
        "X-User-Id": str(other.id),
        "X-Actor": "system:worker",
        "X-Session-Id": str(uuid.uuid4()),
        "X-Username": other.username,
    }
    resp, rid = call(
        w,
        "operator_a",
        "POST",
        f"/targets/{a['target']}/assessments",
        {"name": unique()},
        headers=forged,
    )
    assert resp.status_code == 201
    (event,) = events(w, rid)
    assert_human(event, w, "operator_a", A.ASSESSMENT_CREATED)
    assert event.actor_label == w.users["operator_a"].display_name
    for field in ("actor_user_id", "session_id", "actor", "actor_type", "actor_label", "audit"):
        resp, rid = call(
            w,
            "operator_a",
            "POST",
            f"/targets/{a['target']}/assessments",
            {"name": unique(), field: str(other.id)},
        )
        assert resp.status_code == 422 and events(w, rid) == []


# --- concurrency ---------------------------------------------------------------------------------


def test_concurrent_audited_requests_keep_their_own_actors(world: World) -> None:
    w, a = world, world.ids["a"]
    results: list[tuple[str, int, uuid.UUID]] = []
    lock = threading.Lock()

    def worker(actor: str, kind: str) -> Callable[[], None]:
        def run() -> None:
            client = w.live.client()
            for _ in range(4):
                rid = uuid.uuid4()
                headers = {**bearer(w.tokens[actor]), "X-Request-ID": str(rid)}
                if kind == "create" or kind == "deny":
                    resp = client.post(
                        f"{API}/targets/{a['target']}/assessments",
                        headers=headers,
                        json={"name": unique()},
                    )
                else:
                    resp = client.post(
                        f"{API}/assessments/{a['assessment']}/reports",
                        headers=headers,
                        json={"title": "c", "formats": ["json"], "scan_id": a["scan"]},
                    )
                with lock:
                    results.append((actor, resp.status_code, rid))

        return run

    run_threads(
        worker("owner_a", "create"),
        worker("operator_a", "report"),
        worker("viewer_a", "deny"),
        worker("owner_b", "deny"),
    )
    expected = {
        "owner_a": (201, "assessment.created"),
        "operator_a": (202, "report.requested"),
        "viewer_a": (403, "authz.denied"),
        "owner_b": (404, "authz.denied"),
    }
    for actor, status, rid in results:
        assert status == expected[actor][0], actor
        (event,) = events(w, rid)
        assert event.action == expected[actor][1]
        assert event.actor_user_id == w.users[actor].id


def test_concurrent_triage_and_logins_are_each_recorded(world: World) -> None:
    w, a = world, world.ids["a"]
    fid = w.live.scalar(
        "SELECT id FROM findings WHERE scan_id = :s AND status = 'open' "
        "AND id NOT IN (:f1, :f2) ORDER BY id DESC LIMIT 1",
        s=uuid.UUID(a["scan"]),
        f1=uuid.UUID(a["finding"]),
        f2=uuid.UUID(a["finding_2"]),
    )
    barrier = threading.Barrier(4)
    codes: dict[str, int] = {}

    def triage(actor: str, status: str) -> Callable[[], None]:
        def run() -> None:
            client = w.live.client()
            barrier.wait()
            codes[actor] = client.post(
                f"{API}/findings/{fid}/triage",
                headers=bearer(w.tokens[actor]),
                json={"status": status, "reason": "race"},
            ).status_code

        return run

    def sign_in(name: str) -> Callable[[], None]:
        def run() -> None:
            client = w.live.client()
            barrier.wait()
            codes[name] = login(client, w.users[name].username).status_code

        return run

    run_threads(
        triage("operator_a", "accepted_risk"),
        triage("owner_a", "confirmed"),
        sign_in("viewer_a"),
        sign_in("viewer_b"),
    )
    assert set(codes.values()) == {200}
    triaged = w.live.rows(
        "SELECT actor_user_id, metadata ->> 'to_status' AS to_status FROM "
        "audit_events WHERE action = 'finding.triaged' AND resource_id = :f",
        f=fid,
    )
    assert {(r.actor_user_id, r.to_status) for r in triaged} == {
        (w.users["operator_a"].id, "accepted_risk"),
        (w.users["owner_a"].id, "confirmed"),
    }
    history = w.live.rows(
        "SELECT changed_by_user_id, to_status FROM finding_status_changes WHERE finding_id = :f",
        f=fid,
    )
    assert {(h.changed_by_user_id, h.to_status) for h in history} == {
        (r.actor_user_id, r.to_status) for r in triaged
    }  # one event per transition
