"""Phase 9 M7: account and membership administration, through real sessions
against the M4 two-project world (plus fresh projects and users per test)."""

import json
import threading
import uuid
from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.actors import UserActor
from app.core.audit import AuditAction
from app.core.errors import AuthenticationError, ConflictError
from app.models.enums import GlobalRole, ProjectRole
from app.services.audit import AuditRecorder, AuditService
from app.services.users import UserAdministrationService
from tests.integration.auth_support import PASSWORD, PREFIX, bearer, login
from tests.integration.m4_support import FORBIDDEN, PASSWORD_CHANGE, World, world
from tests.integration.test_m4_enforcement import run_threads, unique

pytestmark = pytest.mark.integration

__all__ = ["world"]

API = "/api/v1"
A = AuditAction
TEMP = "temporary-lab-pass-4821"
SECRET_WORDS = ("password", "hash", "token", "credential", "argon2")


def call(
    w: World, who: str | None, method: str, path: str, body: Any = None, **kw: Any
) -> tuple[Any, uuid.UUID]:
    rid = uuid.uuid4()
    headers = {"X-Request-ID": str(rid), **kw.pop("headers", {})}
    return w.request(who, method, f"{API}{path}", body, headers=headers, **kw), rid


def as_token(
    w: World, token: str, method: str, path: str, body: Any = None, **kw: Any
) -> tuple[Any, uuid.UUID]:
    rid = uuid.uuid4()
    headers = {**bearer(token), "X-Request-ID": str(rid), **kw.pop("headers", {})}
    if body is None:
        return w.client.request(method, f"{API}{path}", headers=headers, **kw), rid
    return w.client.request(method, f"{API}{path}", headers=headers, json=body, **kw), rid


def events(w: World, rid: uuid.UUID) -> list[Any]:
    return w.live.rows("SELECT * FROM audit_events WHERE request_id = :r ORDER BY action", r=rid)


def no_secrets(resp: Any, *values: str) -> None:
    """No key names a secret and no value carries a hash or the given secrets."""
    allowed = {"must_change_password"}

    def keys(node: Any) -> list[str]:
        if isinstance(node, dict):
            return [*node, *(k for v in node.values() for k in keys(v))]
        if isinstance(node, list):
            return [k for v in node for k in keys(v)]
        return []

    for key in keys(resp.json()):
        assert key in allowed or not any(word in key.lower() for word in SECRET_WORDS), key
    for value in ("$argon2", *values):
        assert value not in resp.text, value


def new_username() -> str:
    return f"{PREFIX}m7{uuid.uuid4().hex[:10]}"


def create_user(w: World, *, role: str = "user") -> dict[str, Any]:
    resp, _ = call(
        w,
        "admin",
        "POST",
        "/users",
        {
            "username": new_username(),
            "display_name": "M7 User",
            "password": TEMP,
            "global_role": role,
        },
    )
    assert resp.status_code == 201, resp.text
    body: dict[str, Any] = resp.json()
    return body


def activate(w: World, username: str) -> str:
    """Sign in with the temporary password, change it, return the new token."""
    token = login(w.client, username, TEMP).json()["token"]
    changed = w.client.post(
        f"{API}/auth/password",
        headers=bearer(token),
        json={"current_password": TEMP, "new_password": PASSWORD},
    )
    assert changed.status_code == 200, changed.text
    return str(changed.json()["token"])


def session_of(w: World, user_id: uuid.UUID) -> uuid.UUID:
    sid = w.live.scalar(
        "SELECT id FROM sessions WHERE user_id = :u AND revoked_at IS NULL "
        "ORDER BY created_at DESC LIMIT 1",
        u=user_id,
    )
    return uuid.UUID(str(sid))


# --- account administration -----------------------------------------------------------------


def test_admin_creates_an_account_that_must_change_its_password(world: World) -> None:
    w = world
    name = new_username()
    resp, rid = call(
        w,
        "admin",
        "POST",
        "/users",
        {"username": name, "display_name": "  New Person  ", "password": TEMP},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert set(body) == {
        "id",
        "username",
        "display_name",
        "global_role",
        "is_active",
        "disabled_at",
        "must_change_password",
        "last_login_at",
        "created_at",
    }
    assert (body["username"], body["display_name"], body["global_role"]) == (
        name,
        "New Person",
        "user",
    )
    assert body["is_active"] and body["must_change_password"]
    no_secrets(resp, TEMP)
    stored = w.live.scalar(
        "SELECT password_hash FROM user_credentials WHERE user_id = :u", u=uuid.UUID(body["id"])
    )
    assert stored.startswith("$argon2id$") and TEMP not in stored
    (event,) = events(w, rid)
    assert (event.action, event.actor_user_id, event.session_id) == (
        "user.created",
        w.users["admin"].id,
        session_of(w, w.users["admin"].id),
    )
    assert (event.resource_type, str(event.resource_id)) == ("user", body["id"])
    assert event.metadata["global_role"] == "user" and event.metadata["bootstrap"] is False
    # The temporary password signs in, but only to change it.
    token = login(w.client, name, TEMP).json()["token"]
    assert w.client.get(f"{API}/projects", headers=bearer(token)).json() == PASSWORD_CHANGE
    assert activate(w, name)


def test_only_global_admins_administer_accounts(world: World) -> None:
    w = world
    target = create_user(w)["id"]
    routes = [
        ("POST", "/users", {"username": new_username(), "display_name": "x", "password": TEMP}),
        ("GET", "/users", None),
        ("GET", f"/users/{target}", None),
        ("POST", f"/users/{target}/disable", None),
        ("POST", f"/users/{target}/password-reset", {"new_password": TEMP}),
    ]
    for who in ("owner_a", "operator_a", "viewer_a", "owner_b"):
        for method, path, body in routes:
            resp, rid = call(w, who, method, path, body)
            assert (resp.status_code, resp.json()) == (403, FORBIDDEN), (who, path)
            (event,) = events(w, rid)
            assert (event.action, event.outcome) == ("authz.denied", "denied")
            assert event.metadata["permission"] == "user.admin"
    for method, path, body in routes:
        assert call(w, None, method, path, body)[0].status_code == 401
        assert call(w, "pending", method, path, body)[0].json() == PASSWORD_CHANGE
    assert w.live.scalar("SELECT is_active FROM users WHERE id = :u", u=uuid.UUID(target))


def test_account_input_is_validated_and_never_echoed(world: World) -> None:
    w = world
    for body, field in (
        ({"username": "x", "display_name": "x", "password": TEMP}, "username"),
        ({"username": "bad name!", "display_name": "x", "password": TEMP}, "username"),
        ({"username": new_username(), "display_name": "   ", "password": TEMP}, "display_name"),
        ({"username": new_username(), "display_name": "x", "password": "short"}, "password"),
        (
            {
                "username": new_username(),
                "display_name": "x",
                "password": TEMP,
                "global_role": "root",
            },
            "global_role",
        ),
    ):
        resp, rid = call(w, "admin", "POST", "/users", body)
        assert resp.status_code == 422, (field, resp.text)
        assert events(w, rid) == []
    for extra in (
        {"password_hash": "$argon2id$x"},
        {"is_active": False},
        {"id": str(uuid.uuid4())},
        {"actor_user_id": str(w.users["owner_a"].id)},
        {"must_change_password": False},
    ):
        resp, _ = call(
            w,
            "admin",
            "POST",
            "/users",
            {"username": new_username(), "display_name": "x", "password": TEMP, **extra},
        )
        assert resp.status_code == 422, extra
    weak = "weakpw1"
    resp, _ = call(
        w,
        "admin",
        "POST",
        "/users",
        {"username": new_username(), "display_name": "x", "password": weak},
    )
    assert resp.status_code == 422 and weak not in resp.text  # never echoed


def test_usernames_are_unique_ignoring_case(world: World) -> None:
    w = world
    name = new_username()
    assert (
        call(
            w, "admin", "POST", "/users", {"username": name, "display_name": "x", "password": TEMP}
        )[0].status_code
        == 201
    )
    resp, rid = call(
        w,
        "admin",
        "POST",
        "/users",
        {"username": name.upper(), "display_name": "y", "password": TEMP},
    )
    assert resp.status_code == 409 and resp.json()["field"] == "username"
    (event,) = events(w, rid)
    assert (event.action, event.outcome) == ("user.change_refused", "denied")
    assert event.metadata["reason"] == "username_taken"
    assert (
        w.live.scalar("SELECT count(*) FROM users WHERE lower(username) = lower(:n)", n=name) == 1
    )


def test_listing_and_reading_accounts(world: World) -> None:
    w = world
    created = create_user(w)
    page = w.request("admin", "GET", f"{API}/users", params={"limit": 100})
    assert page.status_code == 200
    names = [u["username"] for u in page.json()]
    assert names == sorted(names)
    no_secrets(page)
    admins = w.request(
        "admin", "GET", f"{API}/users", params={"global_role": "admin", "limit": 100}
    ).json()
    assert admins and {u["global_role"] for u in admins} == {"admin"}
    one = w.request("admin", "GET", f"{API}/users/{created['id']}")
    assert one.json() == created
    for missing in (str(uuid.uuid4()), "not-a-uuid"):
        resp = w.request("admin", "GET", f"{API}/users/{missing}")
        assert (resp.status_code, resp.json()["detail"]) == (404, "user not found")
    assert w.request("admin", "GET", f"{API}/users", params={"limit": 101}).status_code == 422


def test_disabling_revokes_sessions_and_blocks_sign_in(world: World) -> None:
    w = world
    user = create_user(w)
    token = activate(w, user["username"])
    other_token = login(w.client, user["username"], PASSWORD).json()["token"]
    resp, rid = call(w, "admin", "POST", f"/users/{user['id']}/disable")
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False and resp.json()["disabled_at"]
    (event,) = events(w, rid)
    assert (event.action, event.metadata["sessions_revoked"]) == ("user.disabled", 2)
    for t in (token, other_token):
        assert w.client.get(f"{API}/auth/me", headers=bearer(t)).status_code == 401
    assert login(w.client, user["username"], PASSWORD).status_code == 401
    # Never deleted: still listed, still the actor of its history.
    assert w.request("admin", "GET", f"{API}/users/{user['id']}").json()["is_active"] is False
    resp, rid = call(w, "admin", "POST", f"/users/{user['id']}/disable")
    assert resp.status_code == 409
    assert events(w, rid)[0].metadata["reason"] == "already_disabled"


def test_admins_cannot_disable_or_reset_themselves(world: World) -> None:
    w = world
    me = str(w.users["admin"].id)
    for path, body, reason in (
        (f"/users/{me}/disable", None, "self"),
        (f"/users/{me}/password-reset", {"new_password": TEMP}, "self"),
    ):
        resp, rid = call(w, "admin", "POST", path, body)
        assert resp.status_code == 409, resp.text
        (event,) = events(w, rid)
        assert (event.action, event.metadata["reason"]) == ("user.change_refused", reason)
    assert w.request("admin", "GET", f"{API}/auth/me").status_code == 200


def test_the_last_active_admin_cannot_be_disabled(world: World) -> None:
    w = world
    # Service rule: in a transaction where no other administrator is active.
    target = create_user(w, role="admin")["id"]
    actor = UserActor(w.users["owner_a"].id, "x")
    with w.live.factory() as s:
        s.execute(
            text(
                "UPDATE users SET is_active = false, disabled_at = now() "
                "WHERE global_role = 'admin' AND is_active AND id <> :t"
            ),
            {"t": uuid.UUID(target)},
        )
        service = UserAdministrationService(s, w.live.clock, w.live.passwords, AuditService(s))
        with pytest.raises(ConflictError, match="active administrator"):
            service.disable(uuid.UUID(target), actor=actor)
    assert w.live.scalar("SELECT is_active FROM users WHERE id = :t", t=uuid.UUID(target))
    assert (
        w.live.scalar(
            "SELECT count(*) FROM audit_events WHERE action = 'user.change_refused' "
            "AND resource_id = :t AND metadata ->> 'reason' = 'last_admin'",
            t=uuid.UUID(target),
        )
        == 1
    )
    # Database rule, whatever writes: no transaction may leave no active admin.
    with pytest.raises(DBAPIError, match="active administrator"), w.live.engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE users SET is_active = false, disabled_at = now() "
                "WHERE global_role = 'admin' AND is_active"
            )
        )
    with pytest.raises(DBAPIError, match="active administrator"), w.live.engine.begin() as conn:
        conn.execute(text("UPDATE users SET global_role = 'user' WHERE global_role = 'admin'"))
    assert w.request("admin", "GET", f"{API}/users").status_code == 200


def test_password_reset_replaces_the_credential_and_sessions(world: World) -> None:
    w = world
    user = create_user(w)
    token = activate(w, user["username"])
    before = w.live.scalar(
        "SELECT password_hash FROM user_credentials WHERE user_id = :u", u=uuid.UUID(user["id"])
    )
    new_temp = "another-temporary-pass-77"
    resp, rid = call(
        w, "admin", "POST", f"/users/{user['id']}/password-reset", {"new_password": new_temp}
    )
    assert resp.status_code == 200 and resp.json()["must_change_password"] is True
    no_secrets(resp, new_temp)
    (event,) = events(w, rid)
    assert (event.action, event.metadata["sessions_revoked"]) == ("user.password_reset", 1)
    assert new_temp not in json.dumps(event.metadata)
    assert w.client.get(f"{API}/auth/me", headers=bearer(token)).status_code == 401
    assert login(w.client, user["username"], PASSWORD).status_code == 401
    fresh = login(w.client, user["username"], new_temp).json()["token"]
    assert w.client.get(f"{API}/projects", headers=bearer(fresh)).json() == PASSWORD_CHANGE
    after = w.live.scalar(
        "SELECT password_hash FROM user_credentials WHERE user_id = :u", u=uuid.UUID(user["id"])
    )
    assert after != before and after.startswith("$argon2id$")
    weak = call(w, "admin", "POST", f"/users/{user['id']}/password-reset", {"new_password": "x"})[0]
    assert weak.status_code == 422 and '"x"' not in weak.text
    disabled = create_user(w)
    call(w, "admin", "POST", f"/users/{disabled['id']}/disable")
    resp, rid = call(
        w, "admin", "POST", f"/users/{disabled['id']}/password-reset", {"new_password": new_temp}
    )
    assert resp.status_code == 409 and events(w, rid)[0].metadata["reason"] == "disabled"


def test_account_changes_roll_back_without_their_audit(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = world
    original = AuditRecorder.record

    def failing(self: AuditRecorder, action: Any, *args: Any, **kwargs: Any) -> uuid.UUID:
        if action in (A.USER_CREATED, A.MEMBERSHIP_ADDED):
            raise RuntimeError("audit storage unavailable")
        return original(self, action, *args, **kwargs)

    monkeypatch.setattr(AuditRecorder, "record", failing)
    name = new_username()
    with pytest.raises(RuntimeError, match="audit storage"):
        call(
            w, "admin", "POST", "/users", {"username": name, "display_name": "x", "password": TEMP}
        )
    assert w.live.scalar("SELECT count(*) FROM users WHERE username = :n", n=name) == 0
    with pytest.raises(RuntimeError, match="audit storage"):
        call(
            w,
            "owner_a",
            "POST",
            f"/projects/{w.ids['a']['project']}/members",
            {"username": w.users["owner_b"].username, "role": "viewer"},
        )
    assert (
        w.live.scalar(
            "SELECT count(*) FROM project_members WHERE project_id = :p AND user_id = :u",
            p=w.project("a"),
            u=w.users["owner_b"].id,
        )
        == 0
    )


# --- membership ----------------------------------------------------------------------------------


def owned_project(w: World) -> tuple[str, str, dict[str, Any]]:
    """A fresh project, owned by a fresh active user; returns (project, token, owner)."""
    owner = create_user(w)
    token = activate(w, owner["username"])
    project = w.client.post(
        f"{API}/projects", headers=bearer(token), json={"name": unique("m7")}
    ).json()["id"]
    w.created_projects.append(uuid.UUID(project))
    return project, token, owner


def members_of(w: World, project: str) -> dict[str, str]:
    rows = w.live.rows(
        "SELECT user_id, role FROM project_members WHERE project_id = :p", p=uuid.UUID(project)
    )
    return {str(r.user_id): r.role for r in rows}


def test_owners_manage_members(world: World) -> None:
    w = world
    project, token, owner = owned_project(w)
    newcomer = create_user(w)
    newcomer_token = activate(w, newcomer["username"])
    resp, rid = as_token(
        w,
        token,
        "POST",
        f"/projects/{project}/members",
        {"username": newcomer["username"].upper(), "role": "operator"},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["user_id"] == newcomer["id"] and resp.json()["role"] == "operator"
    assert resp.json()["created_by_user_id"] == owner["id"]
    (event,) = events(w, rid)
    assert (event.action, str(event.project_id), str(event.actor_user_id)) == (
        "membership.added",
        project,
        owner["id"],
    )
    assert event.metadata["user_id"] == newcomer["id"] and event.metadata["role"] == "operator"
    assert event.session_id == session_of(w, uuid.UUID(owner["id"]))
    assert (
        w.client.get(f"{API}/projects/{project}", headers=bearer(newcomer_token)).status_code == 200
    )
    listed = w.client.get(f"{API}/projects/{project}/members", headers=bearer(token)).json()
    assert {(m["user_id"], m["role"]) for m in listed} == {
        (owner["id"], "owner"),
        (newcomer["id"], "operator"),
    }
    no_secrets(w.client.get(f"{API}/projects/{project}/members", headers=bearer(token)))

    path = f"/projects/{project}/members/{newcomer['id']}"
    resp, rid = as_token(w, token, "PATCH", path, {"role": "owner"})
    assert resp.json()["role"] == "owner"
    (event,) = events(w, rid)
    assert (event.metadata["from_role"], event.metadata["to_role"]) == ("operator", "owner")
    resp, rid = as_token(w, token, "PATCH", path, {"role": "owner"})  # unchanged: nothing recorded
    assert resp.status_code == 200 and events(w, rid) == []
    resp, rid = as_token(w, token, "DELETE", path)
    assert resp.status_code == 204
    (event,) = events(w, rid)
    assert (event.action, event.metadata["role"]) == ("membership.removed", "owner")
    assert (
        w.client.get(f"{API}/projects/{project}", headers=bearer(newcomer_token)).status_code == 404
    )


def test_member_input_is_validated(world: World) -> None:
    w = world
    project, token, owner = owned_project(w)
    disabled = create_user(w)
    call(w, "admin", "POST", f"/users/{disabled['id']}/disable")
    cases = [
        ({"username": "m2-nobody-here", "role": "viewer"}, 404, "unknown_user"),
        ({"username": disabled["username"], "role": "viewer"}, 409, "user_disabled"),
        ({"username": owner["username"], "role": "viewer"}, 409, "already_member"),
    ]
    for body, status, reason in cases:
        resp, rid = as_token(w, token, "POST", f"/projects/{project}/members", body)
        assert resp.status_code == status, (reason, resp.text)
        (event,) = events(w, rid)
        assert (event.action, event.metadata["reason"]) == ("membership.change_refused", reason)
        assert str(event.project_id) == project
    for body in (
        {"username": owner["username"], "role": "admin"},
        {"username": owner["username"], "role": "superuser"},
        {"username": owner["username"]},
        {"username": owner["username"], "role": "viewer", "project_id": str(uuid.uuid4())},
        {"username": owner["username"], "role": "viewer", "user_id": str(uuid.uuid4())},
        {"username": owner["username"], "role": "viewer", "created_by_user_id": str(uuid.uuid4())},
    ):
        assert (
            as_token(w, token, "POST", f"/projects/{project}/members", body)[0].status_code == 422
        )
    path = f"/projects/{project}/members/{owner['id']}"
    for body in ({"role": "admin"}, {"role": "owner", "user_id": str(uuid.uuid4())}, {}):
        assert as_token(w, token, "PATCH", path, body)[0].status_code == 422


def test_a_project_always_keeps_an_owner(world: World) -> None:
    w = world
    project, token, owner = owned_project(w)
    me = f"/projects/{project}/members/{owner['id']}"
    for method, body, operation in (
        ("PATCH", {"role": "viewer"}, "change_role"),
        ("DELETE", None, "remove"),
    ):
        resp, rid = as_token(w, token, method, me, body)
        assert resp.status_code == 409 and "owner" in resp.json()["detail"]
        (event,) = events(w, rid)
        assert event.metadata == {
            "source": event.metadata["source"],
            "operation": operation,
            "reason": "last_owner",
            "user_id": owner["id"],
        }
    assert members_of(w, project) == {owner["id"]: "owner"}
    # Self-removal and self-demotion are allowed while another owner remains.
    second = create_user(w)
    as_token(
        w,
        token,
        "POST",
        f"/projects/{project}/members",
        {"username": second["username"], "role": "owner"},
    )
    assert as_token(w, token, "PATCH", me, {"role": "operator"})[0].json()["role"] == "operator"
    with pytest.raises(DBAPIError, match="at least one owner"), w.live.engine.begin() as conn:
        conn.execute(
            text("DELETE FROM project_members WHERE project_id = :p AND role = 'owner'"),
            {"p": uuid.UUID(project)},
        )  # the database refuses it too
    # The demoted owner can no longer manage members.
    assert as_token(w, token, "GET", f"/projects/{project}/members")[0].status_code == 403


def test_membership_is_owner_only_and_project_scoped(world: World) -> None:
    w, a, b = world, world.ids["a"], world.ids["b"]
    members = f"/projects/{a['project']}/members"
    member = f"{members}/{a['member_user']}"
    for who, status in (
        ("operator_a", 403),
        ("viewer_a", 403),
        ("owner_b", 404),
        ("admin", 404),
        (None, 401),
    ):
        assert call(w, who, "GET", members)[0].status_code == status, who
        assert (
            call(w, who, "POST", members, {"username": "x", "role": "viewer"})[0].status_code
            == status
        )
        assert call(w, who, "PATCH", member, {"role": "owner"})[0].status_code == status
        assert call(w, who, "DELETE", member)[0].status_code == status
    assert call(w, "pending", "GET", members)[0].json() == PASSWORD_CHANGE
    # Cross-project: A's owner cannot reach B's members, by any id combination.
    for path in (
        f"/projects/{b['project']}/members",
        f"/projects/{b['project']}/members/{b['member_user']}",
        f"/projects/{a['project']}/members/{b['member_user']}",
        f"/projects/{a['project']}/members/not-a-uuid",
    ):
        method = "GET" if path.endswith("/members") else "PATCH"
        resp, _ = call(w, "owner_a", method, path, None if method == "GET" else {"role": "owner"})
        assert resp.status_code == 404, path
    assert members_of(w, b["project"])[b["member_user"]] == "viewer"
    # The global admin joins only when an owner adds them.
    added, _ = call(
        w, "owner_a", "POST", members, {"username": w.users["admin"].username, "role": "viewer"}
    )
    assert added.status_code == 201
    assert call(w, "admin", "GET", f"/projects/{a['project']}")[0].status_code == 200
    assert call(w, "admin", "GET", members)[0].status_code == 403  # a viewer, not an owner
    assert call(w, "owner_a", "DELETE", f"{members}/{w.users['admin'].id}")[0].status_code == 204
    assert call(w, "admin", "GET", f"/projects/{a['project']}")[0].status_code == 404


def test_identity_never_comes_from_the_request(world: World) -> None:
    w = world
    project, token, owner = owned_project(w)
    newcomer = create_user(w)
    forged = {
        "X-User": str(w.users["admin"].id),
        "X-User-Id": str(w.users["admin"].id),
        "X-Actor": "system:worker",
        "X-Username": w.users["admin"].username,
    }
    resp, rid = as_token(
        w,
        token,
        "POST",
        f"/projects/{project}/members",
        {"username": newcomer["username"], "role": "viewer"},
        headers=forged,
    )
    assert resp.status_code == 201
    (event,) = events(w, rid)
    assert str(event.actor_user_id) == owner["id"] and event.actor_type == "user"
    assert resp.json()["created_by_user_id"] == owner["id"]
    resp, rid = call(
        w,
        "owner_a",
        "POST",
        "/users",
        {"username": new_username(), "display_name": "x", "password": TEMP},
        headers=forged,
    )
    assert resp.status_code == 403  # headers grant no administrator rights


# --- concurrency ---------------------------------------------------------------------------------


def test_concurrent_demotions_keep_an_owner(world: World) -> None:
    w = world
    for _ in range(3):
        project, token_1, owner_1 = owned_project(w)
        owner_2 = create_user(w)
        token_2 = activate(w, owner_2["username"])
        as_token(
            w,
            token_1,
            "POST",
            f"/projects/{project}/members",
            {"username": owner_2["username"], "role": "owner"},
        )
        barrier = threading.Barrier(2)
        codes: dict[str, int] = {}

        def demote(
            name: str,
            token: str,
            other: str,
            project: str = project,
            barrier: threading.Barrier = barrier,
            codes: dict[str, int] = codes,
        ) -> Callable[[], None]:
            def run() -> None:
                client = w.live.client()
                barrier.wait()
                codes[name] = client.patch(
                    f"{API}/projects/{project}/members/{other}",
                    headers=bearer(token),
                    json={"role": "viewer"},
                ).status_code

            return run

        run_threads(demote("1", token_1, owner_2["id"]), demote("2", token_2, owner_1["id"]))
        roles = members_of(w, project)
        assert list(roles.values()).count("owner") == 1, (codes, roles)
        assert sorted(codes.values()) in ([200, 403], [200, 409])


def test_concurrent_removals_and_adds(world: World) -> None:
    w = world
    project, token, owner = owned_project(w)
    others = [create_user(w) for _ in range(2)]
    tokens = {owner["id"]: token}
    for other in others:
        as_token(
            w,
            token,
            "POST",
            f"/projects/{project}/members",
            {"username": other["username"], "role": "owner"},
        )
        tokens[other["id"]] = activate(w, other["username"])
    # All three owners removed at once: at least one owner always remains.
    barrier = threading.Barrier(3)
    codes: list[int] = []

    def remove(user_id: str) -> Callable[[], None]:
        def run() -> None:
            client = w.live.client()
            barrier.wait()
            codes.append(
                client.delete(
                    f"{API}/projects/{project}/members/{user_id}", headers=bearer(token)
                ).status_code
            )

        return run

    run_threads(*(remove(u) for u in (owner["id"], others[0]["id"], others[1]["id"])))
    remaining = members_of(w, project)
    assert list(remaining.values()).count("owner") >= 1, (codes, remaining)
    assert codes.count(204) <= 2 and set(codes) <= {204, 404, 409, 401, 403}
    # The same user added twice at once: one membership.
    newcomer = create_user(w)
    owner_token = next(tokens[u] for u, role in remaining.items() if role == "owner")
    barrier2 = threading.Barrier(2)
    adds: list[int] = []

    def add() -> None:
        client = w.live.client()
        barrier2.wait()
        adds.append(
            client.post(
                f"{API}/projects/{project}/members",
                headers=bearer(owner_token),
                json={"username": newcomer["username"], "role": "viewer"},
            ).status_code
        )

    run_threads(add, add)
    assert sorted(adds) == [201, 409]
    assert members_of(w, project)[newcomer["id"]] == "viewer"


def test_last_admin_checks_serialize(world: World) -> None:
    """Deterministic interleaving: one disable is paused just before its
    commit while another disable runs. The second must wait for the first
    (advisory lock) and then refuse, or be refused by the database, so the
    platform never ends with no active administrator."""
    w = world
    first, second = create_user(w, role="admin"), create_user(w, role="admin")
    actor = UserActor(w.users["owner_a"].id, "m7 operator of the service")
    others = [
        r[0]
        for r in w.live.rows(
            "SELECT id FROM users WHERE global_role = 'admin' AND is_active AND id NOT IN (:a, :b)",
            a=uuid.UUID(first["id"]),
            b=uuid.UUID(second["id"]),
        )
    ]
    with w.live.engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET is_active = false, disabled_at = now() WHERE id = ANY(:ids)"),
            {"ids": others},
        )
    reached, release = threading.Event(), threading.Event()
    outcomes: dict[str, str] = {}

    def service(s: Any) -> UserAdministrationService:
        return UserAdministrationService(s, w.live.clock, w.live.passwords, AuditService(s))

    def paused() -> None:
        with w.live.factory() as s:
            commit = s.commit

            def pausing_commit() -> None:
                reached.set()
                release.wait(30)
                commit()

            s.commit = pausing_commit  # type: ignore[method-assign]
            try:
                service(s).disable(uuid.UUID(first["id"]), actor=actor)
                outcomes["first"] = "disabled"
            except Exception as exc:  # recorded and asserted below
                outcomes["first"] = type(exc).__name__

    def racing() -> None:
        with w.live.factory() as s:
            try:
                service(s).disable(uuid.UUID(second["id"]), actor=actor)
                outcomes["second"] = "disabled"
            except Exception as exc:
                outcomes["second"] = type(exc).__name__

    try:
        thread = threading.Thread(target=paused, daemon=True)
        thread.start()
        assert reached.wait(30)
        racer = threading.Thread(target=racing, daemon=True)
        racer.start()
        racer.join(1.5)  # with the lock it is still waiting; without, it has finished
        release.set()
        thread.join(30)
        racer.join(30)
        active = w.live.scalar(
            "SELECT count(*) FROM users WHERE global_role = 'admin' "
            "AND is_active AND id IN (:a, :b)",
            a=uuid.UUID(first["id"]),
            b=uuid.UUID(second["id"]),
        )
        assert active == 1, outcomes
        assert list(outcomes.values()).count("disabled") == 1, outcomes
    finally:
        release.set()
        with w.live.engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET is_active = true, disabled_at = NULL WHERE id = ANY(:ids)"),
                {"ids": others},
            )


def test_concurrent_disables_keep_an_active_admin(world: World) -> None:
    """Two administrators disabling each other while no other administrator
    is active: never zero active administrators."""
    w = world
    first, second = create_user(w, role="admin"), create_user(w, role="admin")
    tokens = {u["id"]: activate(w, u["username"]) for u in (first, second)}
    others = [
        r[0]
        for r in w.live.rows(
            "SELECT id FROM users WHERE global_role = 'admin' AND is_active AND id NOT IN (:a, :b)",
            a=uuid.UUID(first["id"]),
            b=uuid.UUID(second["id"]),
        )
    ]
    with w.live.engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET is_active = false, disabled_at = now() WHERE id = ANY(:ids)"),
            {"ids": others},
        )
    try:
        barrier = threading.Barrier(2)
        codes: list[int] = []

        def disable(actor: dict[str, Any], target: dict[str, Any]) -> Callable[[], None]:
            def run() -> None:
                client = w.live.client()
                barrier.wait()
                codes.append(
                    client.post(
                        f"{API}/users/{target['id']}/disable", headers=bearer(tokens[actor["id"]])
                    ).status_code
                )

            return run

        run_threads(disable(first, second), disable(second, first))
        active = w.live.scalar(
            "SELECT count(*) FROM users WHERE global_role = 'admin' "
            "AND is_active AND id IN (:a, :b)",
            a=uuid.UUID(first["id"]),
            b=uuid.UUID(second["id"]),
        )
        assert active == 1, codes
        assert sorted(codes)[0] == 200 and sorted(codes)[1] in (401, 409)
    finally:
        with w.live.engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET is_active = true, disabled_at = NULL WHERE id = ANY(:ids)"),
                {"ids": others},
            )


def test_a_disabled_member_stays_a_historical_actor(world: World) -> None:
    w = world
    project, token, owner = owned_project(w)
    member = create_user(w)
    member_token = activate(w, member["username"])
    as_token(
        w,
        token,
        "POST",
        f"/projects/{project}/members",
        {"username": member["username"], "role": "operator"},
    )
    call(w, "admin", "POST", f"/users/{member['id']}/disable")
    assert (
        w.client.get(f"{API}/projects/{project}", headers=bearer(member_token)).status_code == 401
    )
    listed = w.client.get(f"{API}/projects/{project}/members", headers=bearer(token)).json()
    assert {m["user_id"]: m["is_active"] for m in listed}[member["id"]] is False
    assert members_of(w, project)[member["id"]] == "operator"
    with w.live.factory() as s, pytest.raises(AuthenticationError):
        AuditService(s).user(
            A.MEMBERSHIP_ADDED,
            UserActor(uuid.UUID(member["id"]), "x"),
            resource=("project", uuid.UUID(project)),
            metadata={"user_id": owner["id"], "role": "viewer"},
        )


def test_global_role_enum_is_closed() -> None:
    assert {r.value for r in GlobalRole} == {"admin", "user"}
    assert {r.value for r in ProjectRole} == {"owner", "operator", "viewer"}
