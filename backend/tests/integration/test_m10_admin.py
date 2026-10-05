"""Phase 9 M10: enabling accounts, global-role administration and the
caller's own project membership, through real sessions against the M4
two-project world (plus fresh users and projects per test)."""

import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.actors import UserActor
from app.core.errors import ConflictError
from app.models.enums import GlobalRole
from app.services.audit import AuditService
from app.services.users import UserAdministrationService
from tests.integration.auth_support import PASSWORD, bearer, login
from tests.integration.m4_support import World, world
from tests.integration.test_m7_admin import (
    API,
    TEMP,
    activate,
    as_token,
    call,
    create_user,
    events,
    members_of,
    no_secrets,
    owned_project,
)

pytestmark = pytest.mark.integration

__all__ = ["world"]


def credential_hash(w: World, user_id: str) -> str:
    return str(
        w.live.scalar(
            "SELECT password_hash FROM user_credentials WHERE user_id = :u", u=uuid.UUID(user_id)
        )
    )


def user_row(w: World, user_id: str) -> Any:
    (row,) = w.live.rows("SELECT * FROM users WHERE id = :u", u=uuid.UUID(user_id))
    return row


def disable(w: World, user_id: str) -> None:
    resp, _ = call(w, "admin", "POST", f"/users/{user_id}/disable")
    assert resp.status_code == 200, resp.text


@contextmanager
def only_admins(w: World, *keep: str) -> Iterator[None]:
    """Deactivates every other active administrator for the test (restored
    afterwards), so the last-administrator rule is reachable."""
    keep_ids = [uuid.UUID(k) for k in keep]
    others = [
        r[0]
        for r in w.live.rows(
            "SELECT id FROM users WHERE global_role = 'admin' AND is_active AND NOT (id = ANY(:k))",
            k=keep_ids,
        )
    ]
    with w.live.engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET is_active = false, disabled_at = now() WHERE id = ANY(:ids)"),
            {"ids": others},
        )
    try:
        yield
    finally:
        with w.live.engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET is_active = true, disabled_at = NULL WHERE id = ANY(:ids)"),
                {"ids": others},
            )


def service(w: World, s: Any) -> UserAdministrationService:
    return UserAdministrationService(s, w.live.clock, w.live.passwords, AuditService(s))


def race(
    w: World,
    first: Callable[[UserAdministrationService], Any],
    second: Callable[[UserAdministrationService], Any],
) -> dict[str, str]:
    """Runs `first` up to its commit, holds it there while `second` starts,
    then lets both finish. Returns each outcome ("ok" or the error's name)."""
    reached, release = threading.Event(), threading.Event()
    outcomes: dict[str, str] = {}

    def paused() -> None:
        with w.live.factory() as s:
            commit = s.commit

            def pausing_commit() -> None:
                reached.set()
                release.wait(30)
                commit()

            s.commit = pausing_commit  # type: ignore[method-assign]
            try:
                first(service(w, s))
                outcomes["first"] = "ok"
            except Exception as exc:  # recorded and asserted by the caller
                outcomes["first"] = type(exc).__name__

    def racing() -> None:
        with w.live.factory() as s:
            try:
                second(service(w, s))
                outcomes["second"] = "ok"
            except Exception as exc:  # recorded and asserted by the caller
                outcomes["second"] = type(exc).__name__

    try:
        a = threading.Thread(target=paused, daemon=True)
        a.start()
        assert reached.wait(30)
        b = threading.Thread(target=racing, daemon=True)
        b.start()
        b.join(1.5)  # with the admins lock it is still waiting here
        release.set()
        a.join(30)
        b.join(30)
    finally:
        release.set()
    return outcomes


def active_admins(w: World, *ids: str) -> int:
    return int(
        w.live.scalar(
            "SELECT count(*) FROM users "
            "WHERE global_role = 'admin' AND is_active AND id = ANY(:ids)",
            ids=[uuid.UUID(i) for i in ids],
        )
    )


# --- enabling accounts ------------------------------------------------------------------------


def test_enabling_lets_the_account_sign_in_again_and_nothing_else(world: World) -> None:
    w = world
    user = create_user(w)
    old_token = activate(w, user["username"])  # password is now PASSWORD
    before = credential_hash(w, user["id"])
    disable(w, user["id"])
    assert login(w.client, user["username"], PASSWORD).status_code == 401

    resp, rid = call(w, "admin", "POST", f"/users/{user['id']}/enable")
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_active"] is True and resp.json()["disabled_at"] is None
    no_secrets(resp, PASSWORD)
    row = user_row(w, user["id"])
    assert row.is_active and row.disabled_at is None
    assert row.must_change_password is False  # unchanged (it was changed at activation)
    assert credential_hash(w, user["id"]) == before  # the password is not reset

    # The sessions revoked when it was disabled stay revoked.
    assert w.client.get(f"{API}/auth/me", headers=bearer(old_token)).status_code == 401
    assert (
        w.live.scalar(
            "SELECT count(*) FROM sessions WHERE user_id = :u AND revoked_at IS NULL",
            u=uuid.UUID(user["id"]),
        )
        == 0
    )
    # The account signs in afresh with its existing password.
    fresh = login(w.client, user["username"], PASSWORD)
    assert fresh.status_code == 200
    assert w.client.get(f"{API}/auth/me", headers=bearer(fresh.json()["token"])).status_code == 200

    (event,) = events(w, rid)
    assert (event.action, event.outcome, str(event.resource_id)) == (
        "user.enabled",
        "success",
        user["id"],
    )
    assert str(event.actor_user_id) == str(w.users["admin"].id)
    assert event.metadata == {"source": "api"} or set(event.metadata) <= {"source"}


def test_enabling_keeps_a_pending_password_change(world: World) -> None:
    w = world
    user = create_user(w)  # must change its temporary password
    disable(w, user["id"])
    resp, _ = call(w, "admin", "POST", f"/users/{user['id']}/enable")
    assert resp.status_code == 200
    assert resp.json()["must_change_password"] is True
    token = login(w.client, user["username"], TEMP).json()["token"]
    projects = w.client.get(f"{API}/projects", headers=bearer(token))
    assert projects.status_code == 403
    assert projects.json()["code"] == "password_change_required"


def test_only_global_administrators_enable_accounts(world: World) -> None:
    w = world
    user = create_user(w)
    disable(w, user["id"])
    for who in ("owner_a", "operator_a", "viewer_a", "owner_b"):
        resp, rid = call(w, who, "POST", f"/users/{user['id']}/enable")
        assert resp.status_code == 403, (who, resp.text)
        assert [e.action for e in events(w, rid)] == ["authz.denied"]
    assert user_row(w, user["id"]).is_active is False
    assert call(w, None, "POST", f"/users/{user['id']}/enable")[0].status_code == 401


def test_enabling_an_active_account_is_refused_and_audited(world: World) -> None:
    w = world
    user = create_user(w)
    resp, rid = call(w, "admin", "POST", f"/users/{user['id']}/enable")
    assert resp.status_code == 409
    (event,) = events(w, rid)
    assert (event.action, event.outcome) == ("user.change_refused", "denied")
    assert event.metadata["operation"] == "enable" and event.metadata["reason"] == "already_active"
    for bad in (str(uuid.uuid4()), "not-a-uuid"):
        assert call(w, "admin", "POST", f"/users/{bad}/enable")[0].status_code == 404


# --- global roles ---------------------------------------------------------------------------


def test_administrators_promote_and_demote_and_sessions_restart(world: World) -> None:
    w = world
    user = create_user(w)
    token = activate(w, user["username"])
    assert w.client.get(f"{API}/users", headers=bearer(token)).status_code == 403

    resp, rid = call(
        w, "admin", "PATCH", f"/users/{user['id']}/global-role", {"global_role": "admin"}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["global_role"] == "admin"
    no_secrets(resp, PASSWORD)
    (event,) = events(w, rid)
    assert event.action == "user.global_role_changed"
    assert {k: event.metadata[k] for k in ("from_role", "to_role", "sessions_revoked")} == {
        "from_role": "user",
        "to_role": "admin",
        "sessions_revoked": 1,
    }
    assert str(event.actor_user_id) == str(w.users["admin"].id)
    # The old session ended with the role change; a new sign-in has the role.
    assert w.client.get(f"{API}/auth/me", headers=bearer(token)).status_code == 401
    token = login(w.client, user["username"], PASSWORD).json()["token"]
    assert w.client.get(f"{API}/users", headers=bearer(token)).status_code == 200

    resp, rid = call(
        w, "admin", "PATCH", f"/users/{user['id']}/global-role", {"global_role": "user"}
    )
    assert resp.status_code == 200 and resp.json()["global_role"] == "user"
    assert events(w, rid)[0].metadata["to_role"] == "user"
    assert w.client.get(f"{API}/auth/me", headers=bearer(token)).status_code == 401
    token = login(w.client, user["username"], PASSWORD).json()["token"]
    assert w.client.get(f"{API}/users", headers=bearer(token)).status_code == 403


def test_an_unchanged_role_changes_and_records_nothing(world: World) -> None:
    w = world
    user = create_user(w)
    token = activate(w, user["username"])
    resp, rid = call(
        w, "admin", "PATCH", f"/users/{user['id']}/global-role", {"global_role": "user"}
    )
    assert resp.status_code == 200
    assert events(w, rid) == []
    assert w.client.get(f"{API}/auth/me", headers=bearer(token)).status_code == 200


def test_only_global_administrators_change_roles(world: World) -> None:
    w = world
    user = create_user(w)
    for who in ("owner_a", "operator_a", "viewer_a"):
        # Including on oneself: no member can make themselves an administrator.
        target = str(w.users[who].id) if who == "owner_a" else user["id"]
        resp, rid = call(w, who, "PATCH", f"/users/{target}/global-role", {"global_role": "admin"})
        assert resp.status_code == 403, (who, resp.text)
        assert [e.action for e in events(w, rid)] == ["authz.denied"]
        assert user_row(w, target).global_role == "user"
    resp, _ = call(w, None, "PATCH", f"/users/{user['id']}/global-role", {"global_role": "admin"})
    assert resp.status_code == 401


def test_administrators_cannot_change_their_own_role(world: World) -> None:
    w = world
    admin = str(w.users["admin"].id)
    for role in ("user", "admin"):
        resp, rid = call(w, "admin", "PATCH", f"/users/{admin}/global-role", {"global_role": role})
        assert resp.status_code == 409, resp.text
        (event,) = events(w, rid)
        assert (event.action, event.metadata["operation"], event.metadata["reason"]) == (
            "user.change_refused",
            "change_global_role",
            "self",
        )
    assert user_row(w, admin).global_role == "admin"


def test_a_disabled_account_cannot_be_promoted(world: World) -> None:
    w = world
    user = create_user(w)
    disable(w, user["id"])
    resp, rid = call(
        w, "admin", "PATCH", f"/users/{user['id']}/global-role", {"global_role": "admin"}
    )
    assert resp.status_code == 409
    assert events(w, rid)[0].metadata["reason"] == "disabled"
    assert user_row(w, user["id"]).global_role == "user"
    # The database refuses it on its own, too.
    with (
        pytest.raises(DBAPIError, match="a disabled account cannot become an administrator"),
        w.live.engine.begin() as conn,
    ):
        conn.execute(
            text("UPDATE users SET global_role = 'admin' WHERE id = :u"),
            {"u": uuid.UUID(user["id"])},
        )
    # Demoting a disabled administrator is allowed (it was not counted).
    admin = create_user(w, role="admin")
    disable(w, admin["id"])
    resp, _ = call(
        w, "admin", "PATCH", f"/users/{admin['id']}/global-role", {"global_role": "user"}
    )
    assert resp.status_code == 200 and resp.json()["global_role"] == "user"


def test_roles_are_a_strict_enum_and_the_path_names_the_account(world: World) -> None:
    w = world
    user, other = create_user(w), create_user(w)
    for body in (
        {"global_role": "root"},
        {"global_role": "ADMIN"},
        {"is_admin": True},
        {},
        {"global_role": "admin", "user_id": other["id"]},
        {"global_role": "admin", "username": other["username"]},
        {"global_role": "admin", "actor_user_id": str(w.users["owner_a"].id)},
    ):
        resp, _ = call(w, "admin", "PATCH", f"/users/{user['id']}/global-role", body)
        assert resp.status_code == 422, (body, resp.text)
    for target in (user, other):
        assert user_row(w, target["id"]).global_role == "user"
    # Identity headers are not identity.
    resp, _ = call(
        w,
        "viewer_a",
        "PATCH",
        f"/users/{user['id']}/global-role",
        {"global_role": "admin"},
        headers={"X-User": str(w.users["admin"].id), "X-User-Id": str(w.users["admin"].id)},
    )
    assert resp.status_code == 403


def test_global_roles_never_touch_project_membership(world: World) -> None:
    w = world
    project, _, owner = owned_project(w)
    before = members_of(w, project)
    outsider = create_user(w)
    outsider_token = activate(w, outsider["username"])
    for target, role in ((outsider, "admin"), (owner, "admin"), (owner, "user")):
        resp, _ = call(
            w, "admin", "PATCH", f"/users/{target['id']}/global-role", {"global_role": role}
        )
        assert resp.status_code == 200
    assert members_of(w, project) == before
    # A promoted non-member still cannot see the project.
    outsider_token = login(w.client, outsider["username"], PASSWORD).json()["token"]
    for path in (
        f"/projects/{project}",
        f"/projects/{project}/membership/me",
        f"/projects/{project}/members",
    ):
        assert as_token(w, outsider_token, "GET", path)[0].status_code == 404, path


def test_the_last_active_administrator_is_kept(world: World) -> None:
    w = world
    x, y = create_user(w, role="admin"), create_user(w, role="admin")
    ux, uy = UserActor(uuid.UUID(x["id"]), "x"), UserActor(uuid.UUID(y["id"]), "y")
    with only_admins(w, x["id"], y["id"]):
        with w.live.factory() as s:
            service(w, s).change_global_role(uuid.UUID(y["id"]), GlobalRole.USER, actor=ux)
        # Y, no longer an administrator, cannot take the last one with it.
        with w.live.factory() as s, pytest.raises(ConflictError, match="active administrator"):
            service(w, s).change_global_role(uuid.UUID(x["id"]), GlobalRole.USER, actor=uy)
        assert active_admins(w, x["id"], y["id"]) == 1
        # The database refuses it on its own.
        with (
            pytest.raises(DBAPIError, match="at least one active administrator"),
            w.live.engine.begin() as conn,
        ):
            conn.execute(
                text("UPDATE users SET global_role = 'user' WHERE id = :u"),
                {"u": uuid.UUID(x["id"])},
            )
        assert active_admins(w, x["id"]) == 1


def test_concurrent_demotions_keep_an_administrator(world: World) -> None:
    w = world
    x, y = create_user(w, role="admin"), create_user(w, role="admin")
    ux, uy = UserActor(uuid.UUID(x["id"]), "x"), UserActor(uuid.UUID(y["id"]), "y")
    with only_admins(w, x["id"], y["id"]):
        outcomes = race(
            w,
            lambda svc: svc.change_global_role(uuid.UUID(y["id"]), GlobalRole.USER, actor=ux),
            lambda svc: svc.change_global_role(uuid.UUID(x["id"]), GlobalRole.USER, actor=uy),
        )
        assert active_admins(w, x["id"], y["id"]) == 1, outcomes
        assert sorted(outcomes.values()) == ["ConflictError", "ok"], outcomes


def test_concurrent_disable_and_demotion_keep_an_administrator(world: World) -> None:
    w = world
    x, y = create_user(w, role="admin"), create_user(w, role="admin")
    ux, uy = UserActor(uuid.UUID(x["id"]), "x"), UserActor(uuid.UUID(y["id"]), "y")
    with only_admins(w, x["id"], y["id"]):
        outcomes = race(
            w,
            lambda svc: svc.disable(uuid.UUID(y["id"]), actor=ux),
            lambda svc: svc.change_global_role(uuid.UUID(x["id"]), GlobalRole.USER, actor=uy),
        )
        assert active_admins(w, x["id"], y["id"]) == 1, outcomes
        assert list(outcomes.values()).count("ok") == 1, outcomes


def test_concurrent_promotion_and_demotion_both_succeed(world: World) -> None:
    w = world
    x, y, z = create_user(w, role="admin"), create_user(w, role="admin"), create_user(w)
    ux = UserActor(uuid.UUID(x["id"]), "x")
    with only_admins(w, x["id"], y["id"]):
        outcomes = race(
            w,
            lambda svc: svc.change_global_role(uuid.UUID(y["id"]), GlobalRole.USER, actor=ux),
            lambda svc: svc.change_global_role(uuid.UUID(z["id"]), GlobalRole.ADMIN, actor=ux),
        )
        assert outcomes == {"first": "ok", "second": "ok"}, outcomes
        assert active_admins(w, x["id"], y["id"], z["id"]) == 2


def test_concurrent_enable_and_disable_of_one_account_stay_consistent(world: World) -> None:
    w = world
    user = create_user(w)
    disable(w, user["id"])
    actor = UserActor(w.users["admin"].id, "admin")
    outcomes = race(
        w,
        lambda svc: svc.enable(uuid.UUID(user["id"]), actor=actor),
        lambda svc: svc.disable(uuid.UUID(user["id"]), actor=actor),
    )
    # Serialized on the account row: enabled, then disabled again.
    assert outcomes == {"first": "ok", "second": "ok"}, outcomes
    row = user_row(w, user["id"])
    assert row.is_active is False and row.disabled_at is not None


# --- the caller's own membership --------------------------------------------------------------


def test_members_read_their_own_role_and_nothing_else(world: World) -> None:
    w = world
    pid = w.ids["a"]["project"]
    for who, role in (("owner_a", "owner"), ("operator_a", "operator"), ("viewer_a", "viewer")):
        resp, rid = call(w, who, "GET", f"/projects/{pid}/membership/me")
        assert resp.status_code == 200, (who, resp.text)
        assert resp.json() == {"project_id": pid, "user_id": str(w.users[who].id), "role": role}
        # Reading one's own role is not security history.
        assert events(w, rid) == []


def test_identity_comes_from_the_session_only(world: World) -> None:
    w = world
    pid = w.ids["a"]["project"]
    owner = str(w.users["owner_a"].id)
    resp, _ = call(
        w,
        "viewer_a",
        "GET",
        f"/projects/{pid}/membership/me",
        params={"user_id": owner},
        headers={"X-User-Id": owner, "X-User": "owner_a", "X-Actor": owner},
    )
    assert resp.status_code == 200
    assert resp.json()["user_id"] == str(w.users["viewer_a"].id)
    assert resp.json()["role"] == "viewer"
    assert owner not in resp.text


def test_non_members_cannot_tell_a_project_exists(world: World) -> None:
    w = world
    pid = w.ids["a"]["project"]
    for who in ("owner_b", "viewer_b", "admin"):
        resp, _ = call(w, who, "GET", f"/projects/{pid}/membership/me")
        assert resp.status_code == 404, (who, resp.text)
    for bad in (str(uuid.uuid4()), "not-a-uuid", "..%2Fusers"):
        assert call(w, "owner_a", "GET", f"/projects/{bad}/membership/me")[0].status_code == 404
    assert call(w, None, "GET", f"/projects/{pid}/membership/me")[0].status_code == 401


def test_the_membership_path_decides_the_project(world: World) -> None:
    """PATCH /projects/A/members/B cannot be redirected to another project or
    member by the body (M4 containment, M7 schemas)."""
    w = world
    pa, pb = w.ids["a"]["project"], w.ids["b"]["project"]
    member_b = w.ids["b"]["member_user"]
    before = members_of(w, pb)
    for body in (
        {"role": "owner", "project_id": pb},
        {"role": "owner", "user_id": member_b},
        {"role": "owner", "project": pb},
    ):
        resp, _ = call(
            w, "owner_a", "PATCH", f"/projects/{pa}/members/{w.ids['a']['member_user']}", body
        )
        assert resp.status_code == 422, (body, resp.text)
    # A member of B named under A's path is not found.
    resp, _ = call(w, "owner_a", "PATCH", f"/projects/{pa}/members/{member_b}", {"role": "owner"})
    assert resp.status_code == 404
    assert members_of(w, pb) == before
