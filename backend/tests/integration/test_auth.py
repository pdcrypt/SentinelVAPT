"""Phase 9 M2 authentication core (ADR 0014): login, sessions, logout,
password change, disabled users, throttling, timing and response security.

Authentication only answers who the user is: no existing route is protected
in M2 (test_existing_routes_are_unchanged)."""

import hashlib
import statistics
import threading
import time
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.passwords import Argon2Parameters, Passwords
from app.services.audit import AuditContext
from app.services.auth import AuthService
from tests.integration.auth_support import (
    PASSWORD,
    PREFIX,
    Live,
    bearer,
    live,
    login,
)

pytestmark = pytest.mark.integration

__all__ = ["live"]  # fixture re-exported for this module

NEW_PASSWORD = "a-brand-new-passphrase-42"  # noqa: S105  # test fixture
INVALID = {"detail": "Invalid username or password.", "code": "invalid_credentials", "field": None}
UNAUTHENTICATED = {"detail": "Authentication required.", "code": "unauthenticated", "field": None}


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def failure_reasons(live: Live, user_id: uuid.UUID) -> list[str]:
    rows = live.rows(
        "SELECT metadata ->> 'reason' FROM audit_events WHERE action = 'auth.login_failed' "
        "AND resource_id = :u ORDER BY occurred_at, id",
        u=user_id,
    )
    return [r[0] for r in rows]


def service(live: Live) -> tuple[AuthService, Any]:
    session = live.factory()
    return AuthService(session, live.settings, live.clock, live.passwords), session


# --- login ----------------------------------------------------------------------------------


def test_successful_login_returns_a_token_whose_hash_is_stored(live: Live) -> None:
    user = live.user("alice")
    client = live.client()
    resp = login(client, user.username)
    assert resp.status_code == 200, resp.text
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    token = body["token"]
    assert body["token_type"] == "bearer"  # noqa: S105  # the scheme name
    assert len(token) >= 43
    assert body["user"] == {
        "id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "global_role": "user",
        "must_change_password": False,
    }
    assert set(body) == {"user", "session", "token", "token_type"}
    stored = live.rows("SELECT token_sha256, created_at, idle_expires_at, expires_at "
                       "FROM sessions WHERE user_id = :u", u=user.id)  # fmt: skip
    assert len(stored) == 1
    assert stored[0][0] == sha256(token)
    assert stored[0][2] - stored[0][1] == live.clock() - live.clock() + (
        stored[0][2] - stored[0][1]
    )
    assert (stored[0][2] - stored[0][1]).total_seconds() == 30 * 60
    assert (stored[0][3] - stored[0][1]).total_seconds() == 12 * 3600
    # The raw token is stored nowhere.
    assert live.scalar("SELECT count(*) FROM sessions WHERE token_sha256 = :t OR "
                       "user_agent = :t", t=token) == 0  # fmt: skip
    assert live.scalar("SELECT count(*) FROM audit_events WHERE metadata::text LIKE :t",
                       t=f"%{token}%") == 0  # fmt: skip
    assert live.scalar("SELECT last_login_at IS NOT NULL FROM users WHERE id = :u", u=user.id)


def test_failures_are_uniform_and_create_nothing(live: Live) -> None:
    user = live.user("bob")
    disabled = live.user("carol", active=False)
    client = live.client()
    cases = {
        "unknown": login(client, f"{PREFIX}nobody-here"),
        "unknown_bad_format": login(client, "no such user!"),
        "wrong_password": login(client, user.username, "wrong-password-123"),
        "disabled_correct_password": login(client, disabled.username),
        "case_variant_wrong": login(client, user.username.upper(), "wrong-password-123"),
    }
    for name, resp in cases.items():
        assert resp.status_code == 401, name
        assert resp.json() == INVALID, name
        assert resp.headers["www-authenticate"] == "Bearer", name
    assert live.scalar(f"SELECT count(*) FROM users WHERE username LIKE '{PREFIX}nobody%'") == 0  # noqa: S608
    assert live.scalar("SELECT count(*) FROM sessions WHERE user_id IN (:a, :b)",
                       a=user.id, b=disabled.id) == 0  # fmt: skip
    assert failure_reasons(live, user.id) == ["bad_password", "bad_password"]
    assert failure_reasons(live, disabled.id) == ["disabled"]
    # Usernames are case-insensitive for login.
    assert login(client, user.username.upper()).status_code == 200


def test_unknown_usernames_are_never_recorded(live: Live) -> None:
    client = live.client()
    login(client, f"{PREFIX}secret-sounding-name", "typed-a-password-into-username")
    rows = live.rows("SELECT metadata::text, resource_id FROM audit_events "
                     "WHERE action = 'auth.login_failed' AND metadata ->> 'source' = :s",
                     s="198.51.100.7")  # fmt: skip
    assert rows and all(r[1] is None for r in rows)
    for meta, _ in rows:
        assert "secret-sounding-name" not in meta
        assert "typed-a-password" not in meta
        assert '"reason": "unknown_user"' in meta


def test_rehash_on_login_upgrades_outdated_parameters(live: Live) -> None:
    weak = Argon2Parameters(time_cost=1, memory_kib=8192, parallelism=1)
    user = live.user("legacy-hash", params=weak)
    before = live.scalar("SELECT password_hash FROM user_credentials WHERE user_id = :u", u=user.id)
    assert before.startswith("$argon2id$v=19$m=8192,t=1,p=1$")
    assert login(live.client(), user.username).status_code == 200
    after = live.scalar("SELECT password_hash FROM user_credentials WHERE user_id = :u", u=user.id)
    assert after.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert after != before
    assert login(live.client(), user.username).status_code == 200  # still the same password


def test_presented_tokens_never_become_the_session(live: Live) -> None:
    """Session fixation: login always issues a fresh random token, whatever
    token (valid or attacker-chosen) accompanies the request."""
    user = live.user("fixation")
    client = live.client()
    first = login(client, user.username).json()["token"]
    attacker = "attacker-chosen-token-" + "x" * 30
    for presented in (first, attacker):
        client.cookies.set("__Host-sv_session", presented)
        resp = login(client, user.username, headers=bearer(presented))
        client.cookies.clear()
        issued = resp.json()["token"]
        assert issued not in (first, attacker)
    assert client.get("/api/v1/auth/me", headers=bearer(attacker)).status_code == 401
    assert live.scalar("SELECT count(*) FROM sessions WHERE token_sha256 = :h",
                       h=sha256(attacker)) == 0  # fmt: skip


# --- session validation ---------------------------------------------------------------------


def test_me_and_session_validation(live: Live) -> None:
    user = live.user("dave")
    client = live.client()
    token = login(client, user.username).json()["token"]
    me = client.get("/api/v1/auth/me", headers=bearer(token))
    assert me.status_code == 200
    assert me.json()["user"]["username"] == user.username
    assert set(me.json()) == {"user", "session"}  # no token, no project information
    bad = [
        {},
        bearer(""),
        bearer("not-a-real-token"),
        bearer(token + "x"),
        bearer("x" * 300),
        {"Authorization": f"Basic {token}"},
        {"Authorization": token},
    ]
    for headers in bad:
        resp = client.get("/api/v1/auth/me", headers=headers)
        assert resp.status_code == 401, headers
        assert resp.json() == UNAUTHENTICATED
        assert resp.headers["www-authenticate"] == "Bearer"


def test_cookies_and_query_parameters_are_never_credentials(live: Live) -> None:
    user = live.user("cookie")
    client = live.client()
    token = login(client, user.username).json()["token"]
    for name in ("__Host-sv_session", "sv_session", "session", "token", "Authorization"):
        client.cookies.set(name, token)
        assert client.get("/api/v1/auth/me").status_code == 401
        client.cookies.clear()
    assert client.get(f"/api/v1/auth/me?token={token}").status_code == 401
    assert client.get(f"/api/v1/auth/me?access_token={token}").status_code == 401


def test_idle_and_absolute_expiry(live: Live) -> None:
    user = live.user("expiry")
    client = live.client()
    token = login(client, user.username).json()["token"]
    # Idle: 30 minutes without activity.
    live.advance(minutes=29, seconds=59)
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 200
    live.advance(minutes=30)  # the request above moved the idle expiry forward
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401
    # Absolute: activity every 20 minutes keeps it alive only until 12 hours.
    token = login(client, user.username).json()["token"]
    created = live.clock()
    while live.clock() - created < __import__("datetime").timedelta(hours=11, minutes=40):
        live.advance(minutes=20)
        assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 200
    live.advance(minutes=20)  # 12 hours after login
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


def test_last_seen_only_moves_forward(live: Live) -> None:
    user = live.user("seen")
    client = live.client()
    token = login(client, user.username).json()["token"]
    h = sha256(token)

    def seen() -> Any:
        return live.rows("SELECT last_seen_at, idle_expires_at FROM sessions "
                         "WHERE token_sha256 = :h", h=h)[0]  # fmt: skip

    start = seen()
    live.advance(seconds=30)  # below the 1-minute resolution: no write
    client.get("/api/v1/auth/me", headers=bearer(token))
    assert seen() == start
    live.advance(minutes=2)
    client.get("/api/v1/auth/me", headers=bearer(token))
    moved = seen()
    assert moved[0] > start[0] and moved[1] > start[1]
    live.advance(minutes=-5)  # a clock going backwards never moves activity back
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 200
    assert seen() == moved


# --- logout ---------------------------------------------------------------------------------


def test_logout_revokes_only_the_current_session(live: Live) -> None:
    user = live.user("erin")
    client = live.client()
    a = login(client, user.username).json()["token"]
    b = login(client, user.username).json()["token"]
    resp = client.post("/api/v1/auth/logout", headers=bearer(a))
    assert resp.status_code == 204 and resp.content == b""
    assert client.get("/api/v1/auth/me", headers=bearer(a)).status_code == 401
    assert client.get("/api/v1/auth/me", headers=bearer(b)).status_code == 200
    # Repeated logout is refused safely, and revocation is final.
    again = client.post("/api/v1/auth/logout", headers=bearer(a))
    assert again.status_code == 401 and again.json() == UNAUTHENTICATED
    assert live.rows("SELECT revoked_reason FROM sessions WHERE token_sha256 = :h",
                     h=sha256(a)) == [("logout",)]  # fmt: skip
    assert client.post("/api/v1/auth/logout").status_code == 401


# --- password change ------------------------------------------------------------------------


def change(client: TestClient, token: str, current: str, new: str) -> Any:
    return client.post("/api/v1/auth/password", headers=bearer(token),
                       json={"current_password": current, "new_password": new})  # fmt: skip


def test_password_change_rotates_every_session(live: Live) -> None:
    user = live.user("frank")
    client = live.client()
    current = login(client, user.username).json()["token"]
    other = login(client, user.username).json()["token"]
    before = live.scalar("SELECT password_hash FROM user_credentials WHERE user_id = :u", u=user.id)
    resp = change(client, current, PASSWORD, NEW_PASSWORD)
    assert resp.status_code == 200, resp.text
    fresh = resp.json()["token"]
    assert fresh not in (current, other)
    for old in (current, other):
        assert client.get("/api/v1/auth/me", headers=bearer(old)).status_code == 401
    assert client.get("/api/v1/auth/me", headers=bearer(fresh)).status_code == 200
    after = live.scalar("SELECT password_hash FROM user_credentials WHERE user_id = :u", u=user.id)
    assert after != before and after.startswith("$argon2id$")
    assert sorted(r[0] for r in live.rows(
        "SELECT revoked_reason FROM sessions WHERE user_id = :u AND revoked_at IS NOT NULL",
        u=user.id)) == ["password_changed", "password_changed"]  # fmt: skip
    assert login(client, user.username, PASSWORD).status_code == 401
    assert login(client, user.username, NEW_PASSWORD).status_code == 200


def test_password_change_checks(live: Live) -> None:
    user = live.user("grace-long-name")
    client = live.client()
    token = login(client, user.username).json()["token"]
    assert client.post("/api/v1/auth/password", json={"current_password": PASSWORD,
                       "new_password": NEW_PASSWORD}).status_code == 401  # fmt: skip
    wrong = change(client, token, "not-my-password-1", NEW_PASSWORD)
    assert wrong.status_code == 403
    assert wrong.json() == {
        "detail": "The current password is incorrect.",
        "code": "invalid_current_password",
        "field": "current_password",
    }
    for new, message in [
        ("short", "at least 12"),
        (PASSWORD, "must differ"),
        (user.username.upper(), "not be the username"),
        ("x" * 257, "at most 256"),
    ]:
        resp = change(client, token, PASSWORD, new)
        assert resp.status_code == 422, new
        assert message in resp.text
        assert resp.json()["field"] == "new_password"
        if new != user.username.upper():
            assert new not in resp.text  # never echoed
    # A failed change keeps the session and the password.
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 200
    assert login(client, user.username).status_code == 200


def test_validation_errors_never_echo_passwords(live: Live) -> None:
    client = live.client()
    secret = "secret-\x00-password-value"  # noqa: S105  # test input
    resp = client.post("/api/v1/auth/login", json={"username": "x", "password": secret})
    assert resp.status_code == 422
    assert "secret-" not in resp.text
    long_secret = "s3cret" * 200
    resp = client.post("/api/v1/auth/login", json={"username": "x", "password": long_secret})
    assert resp.status_code == 422
    assert "s3cret" not in resp.text


# --- disabled users -------------------------------------------------------------------------


def test_disabling_a_user_ends_their_sessions(live: Live) -> None:
    user = live.user("heidi")
    client = live.client()
    a = login(client, user.username).json()["token"]
    b = login(client, user.username).json()["token"]
    auth, session = service(live)
    with session:
        revoked = auth.disable_user(user.id, AuditContext(None, "m2-test"), actor="m2-test")
    assert revoked == 2
    for token in (a, b):
        resp = client.get("/api/v1/auth/me", headers=bearer(token))
        assert resp.status_code == 401 and resp.json() == UNAUTHENTICATED
    disabled = login(client, user.username)
    assert disabled.status_code == 401 and disabled.json() == INVALID


def test_a_disabled_flag_alone_stops_existing_sessions(live: Live) -> None:
    """Even without the revocation (e.g. disabled directly in the database),
    validation refuses sessions of inactive users."""
    user = live.user("ivan")
    client = live.client()
    token = login(client, user.username).json()["token"]
    with live.engine.begin() as conn:
        conn.exec_driver_sql(
            "UPDATE users SET is_active = false, disabled_at = now() WHERE id = %s", (user.id,)
        )
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


# --- throttling -----------------------------------------------------------------------------


def test_account_throttling_is_uniform_and_temporary(live: Live) -> None:
    user = live.user("judy")
    client = live.client()
    for _ in range(3):  # threshold
        assert login(client, user.username, "wrong-password-xx").status_code == 401
    throttled = login(client, user.username)  # the correct password, but throttled
    assert throttled.status_code == 401 and throttled.json() == INVALID
    assert failure_reasons(live, user.id)[-1] == "throttled"
    time.sleep(1.3)  # max delay is 1.2 s: no permanent lockout
    assert login(client, user.username).status_code == 200
    # A successful login resets the account count.
    for _ in range(2):
        login(client, user.username, "wrong-password-xx")
    assert login(client, user.username).status_code == 200


def test_throttling_is_per_account_and_per_source(live: Live) -> None:
    a, b = live.user("ken"), live.user("lea")
    client = live.client("198.51.100.10")
    for _ in range(4):
        login(client, a.username, "wrong-password-xx")
    assert login(client, a.username).status_code == 401  # account a throttled
    assert login(client, b.username).status_code == 200  # account b unaffected

    noisy = live.client("198.51.100.20", auth_throttle_source_threshold=5)
    for i in range(5):
        login(noisy, f"{PREFIX}missing-{i}")
    blocked = login(noisy, b.username)
    assert blocked.status_code == 401 and blocked.json() == INVALID  # same response
    quiet = live.client("198.51.100.30", auth_throttle_source_threshold=5)
    assert login(quiet, b.username).status_code == 200  # another source is unaffected


def test_concurrent_failures_are_all_counted(live: Live) -> None:
    user = live.user("mallory-target")
    client = live.client()
    barrier = threading.Barrier(8)
    statuses: list[int] = []
    lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        resp = login(client, user.username, "wrong-password-xx")
        with lock:
            statuses.append(resp.status_code)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert statuses == [401] * 8
    reasons = failure_reasons(live, user.id)
    assert len(reasons) == 8  # insert-only: nothing lost
    # Attempts are serialized per account (advisory lock): exactly 3 were
    # checked against the password before the account was throttled. (Their
    # order cannot be read from occurred_at, which is transaction start time.)
    assert sorted(reasons) == ["bad_password"] * 3 + ["throttled"] * 5


def test_every_login_runs_exactly_one_argon2_verification(
    live: Live, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unknown users are verified against the dummy hash; disabled users and
    throttled attempts are verified too, so no path skips the work."""
    calls: list[str] = []
    original = Passwords.verify

    def spy(self: Passwords, stored: str, password: str) -> bool:
        calls.append(stored)
        return original(self, stored, password)

    monkeypatch.setattr(Passwords, "verify", spy)
    disabled = live.user("verify-disabled", active=False)
    client = live.client()
    login(client, f"{PREFIX}ghost-account")
    assert calls == [live.passwords.dummy_hash]
    calls.clear()
    login(client, disabled.username)
    stored = live.scalar("SELECT password_hash FROM user_credentials WHERE user_id = :u",
                         u=disabled.id)  # fmt: skip
    assert calls == [stored]


# --- timing ---------------------------------------------------------------------------------


def test_unknown_users_cost_the_same_argon2_work(live: Live) -> None:
    """Coarse: an unknown username must not be dramatically faster than a
    wrong password (it would be ~100x faster if the dummy verification were
    skipped). Medians of several runs, generous ratio."""
    user = live.user("timing")
    client = live.client("198.51.100.40")

    def median(username: str) -> float:
        samples = []
        for _ in range(7):
            started = time.perf_counter()
            login(client, username, "wrong-password-xx")
            samples.append(time.perf_counter() - started)
        return statistics.median(samples)

    login(client, user.username, "warm-up-password")
    known = median(user.username)
    unknown = median(f"{PREFIX}does-not-exist")
    assert unknown > 0.5 * known, (unknown, known)


# --- concurrency ----------------------------------------------------------------------------


def test_concurrent_logins_get_distinct_sessions(live: Live) -> None:
    user = live.user("nina")
    client = live.client()
    tokens: list[str] = []
    lock = threading.Lock()

    def attempt() -> None:
        resp = login(client, user.username)
        with lock:
            tokens.append(resp.json()["token"])

    threads = [threading.Thread(target=attempt) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert len(set(tokens)) == 5
    assert live.scalar("SELECT count(*) FROM sessions WHERE user_id = :u", u=user.id) == 5


def test_concurrent_password_changes_cannot_both_win(live: Live) -> None:
    user = live.user("oscar")
    client = live.client()
    token = login(client, user.username).json()["token"]
    barrier = threading.Barrier(2)
    results: list[int] = []
    lock = threading.Lock()

    def attempt(new: str) -> None:
        barrier.wait()
        resp = change(client, token, PASSWORD, new)
        with lock:
            results.append(resp.status_code)

    threads = [threading.Thread(target=attempt, args=(p,))
               for p in ("first-new-passphrase-1", "second-new-passphrase-2")]  # fmt: skip
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert sorted(results)[0] == 200 and sorted(results)[1] in (401, 403)
    assert live.scalar("SELECT count(*) FROM sessions WHERE user_id = :u "
                       "AND revoked_at IS NULL", u=user.id) == 1  # fmt: skip


def test_concurrent_logout_and_password_change(live: Live) -> None:
    user = live.user("peggy")
    client = live.client()
    token = login(client, user.username).json()["token"]
    barrier = threading.Barrier(2)
    out: dict[str, Any] = {}

    def do_logout() -> None:
        barrier.wait()
        try:
            out["logout"] = client.post("/api/v1/auth/logout", headers=bearer(token)).status_code
        except Exception as exc:  # reported by the assertion below
            out["logout"] = repr(exc)

    def do_change() -> None:
        barrier.wait()
        try:
            out["change"] = change(client, token, PASSWORD, NEW_PASSWORD).status_code
        except Exception as exc:  # reported by the assertion below
            out["change"] = repr(exc)

    threads = [threading.Thread(target=do_logout), threading.Thread(target=do_change)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert out.get("logout") in (204, 401) and out.get("change") in (200, 401), out
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


# --- response security ----------------------------------------------------------------------


def test_no_response_leaks_secrets(live: Live) -> None:
    user = live.user("quinn")
    client = live.client()
    token = login(client, user.username).json()["token"]
    stored_hash = live.scalar("SELECT password_hash FROM user_credentials WHERE user_id = :u",
                              u=user.id)  # fmt: skip
    responses = [
        login(client, user.username, "wrong-password-xx"),
        login(client, f"{PREFIX}nobody"),
        client.get("/api/v1/auth/me", headers=bearer(token)),
        client.get("/api/v1/auth/me", headers=bearer("bogus-token")),
        client.get("/api/v1/auth/me", headers={"Cookie": "sv_session=cookie-secret-value"}),
        change(client, token, "wrong-password-xx", NEW_PASSWORD),
        change(client, token, PASSWORD, "short"),
        client.post("/api/v1/auth/login", json={"username": 1, "password": ["x"]}),
    ]
    for resp in responses:
        text = resp.text
        for secret in (PASSWORD, stored_hash, "$argon2", sha256(token), "cookie-secret-value",
                       "Traceback", "psycopg", "sqlalchemy", "Bearer "):  # fmt: skip
            assert secret not in text, (resp.request.url, secret)
    me = client.get("/api/v1/auth/me", headers=bearer(token)).text
    assert token not in me


def test_product_routes_require_a_session(live: Live) -> None:
    """Since Phase 9 M4 every product route needs a valid session; only
    health, readiness and login are public."""
    client = live.client()
    assert client.get("/api/v1/projects").status_code == 401
    assert client.get("/api/v1/rules").status_code == 401
    assert client.get("/api/v1/health").status_code == 200
    token = login(client, live.user().username).json()["token"]
    assert client.get("/api/v1/projects", headers=bearer(token)).json() == []
    assert client.get("/api/v1/rules", headers=bearer(token)).status_code == 200
