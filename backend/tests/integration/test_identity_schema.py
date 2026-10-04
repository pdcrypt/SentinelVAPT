"""Phase 9 M1: the identity, membership, session and audit schema enforces its
rules in the database (ADR 0014), whatever the application does later."""

import threading
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.models import AuditEvent, Project, ProjectMember, User, UserSession
from app.models.enums import AuditActorType, AuditOutcome, GlobalRole, ProjectRole

pytestmark = pytest.mark.integration

ARGON2_HASH = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2g"
TOKEN_HASH = "a" * 64


def rejected(
    session: Session, sql: str, params: dict[str, Any] | None = None, match: str | None = None
) -> None:
    """Assert that `sql` fails in the database (inside its own savepoint)."""
    with pytest.raises(DBAPIError, match=match), session.begin_nested():
        session.execute(text(sql), params or {})
        session.flush()


def deferred_check_fails(session: Session, match: str) -> None:
    """Run the deferred constraints now, as COMMIT would, expecting a failure."""
    with pytest.raises(DBAPIError, match=match), session.begin_nested():
        session.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
    session.execute(text("SET CONSTRAINTS ALL DEFERRED"))


def deferred_check_passes(session: Session) -> None:
    session.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
    session.execute(text("SET CONSTRAINTS ALL DEFERRED"))


def make_user(session: Session, username: str | None = None, **kw: Any) -> User:
    user = User(
        username=username or f"user-{uuid.uuid4().hex[:12]}",
        display_name=kw.pop("display_name", "Test User"),
        **kw,
    )
    session.add(user)
    session.flush()
    return user


def make_project(session: Session) -> Project:
    project = Project(name=f"p-{uuid.uuid4().hex[:12]}")
    session.add(project)
    session.flush()
    return project


def add_member(session: Session, project: Project, user: User, role: ProjectRole) -> None:
    session.add(ProjectMember(project_id=project.id, user_id=user.id, role=role))
    session.flush()


def insert_session(session: Session, user: User, **overrides: Any) -> uuid.UUID:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "user_id": user.id,
        "token_sha256": uuid.uuid4().hex + uuid.uuid4().hex,
        "idle": "now() + interval '30 minutes'",
        "expires": "now() + interval '12 hours'",
    }
    values.update(overrides)
    # idle/expires are SQL expressions chosen by the tests themselves.
    sql = (
        "INSERT INTO sessions (id, user_id, token_sha256, idle_expires_at, expires_at) "  # noqa: S608
        f"VALUES (:id, :user_id, :token_sha256, {values['idle']}, {values['expires']})"
    )
    session.execute(text(sql), {k: values[k] for k in ("id", "user_id", "token_sha256")})
    session_id: uuid.UUID = values["id"]
    return session_id


def insert_audit(session: Session, **overrides: Any) -> uuid.UUID:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "actor_type": "system",
        "actor_user_id": None,
        "action": "scan.launched",
        "outcome": "success",
        "project_id": None,
        "resource_type": None,
        "resource_id": None,
        "metadata": "{}",
        "occurred_at": None,
    }
    values.update(overrides)
    session.execute(
        text(
            "INSERT INTO audit_events (id, actor_type, actor_user_id, action, outcome, project_id, "
            "resource_type, resource_id, metadata, occurred_at) VALUES (:id, :actor_type, "
            ":actor_user_id, :action, :outcome, :project_id, :resource_type, :resource_id, "
            "CAST(:metadata AS jsonb), COALESCE(CAST(:occurred_at AS timestamptz), now()))"
        ),
        values,
    )
    event_id: uuid.UUID = values["id"]
    return event_id


# --- schema shape -------------------------------------------------------------------------


def test_no_plaintext_credential_or_token_columns(db_session: Session) -> None:
    inspector = inspect(db_session.connection())
    columns = {
        table: {c["name"] for c in inspector.get_columns(table)}
        for table in ("users", "user_credentials", "sessions", "audit_events")
    }
    assert "password" not in columns["users"] | columns["user_credentials"]
    # The only password-related column on users is a boolean flag; hashes live
    # in user_credentials.
    assert {c for c in columns["users"] if "password" in c} == {"must_change_password"}
    assert not columns["users"] & {"password_hash", "hash", "salt"}
    assert columns["user_credentials"] >= {"password_hash"}
    assert "token" not in columns["sessions"]
    assert "token_sha256" in columns["sessions"]
    assert {"idle_expires_at", "expires_at", "revoked_at", "revoked_reason"} <= columns["sessions"]
    assert not columns["audit_events"] & {"password", "token", "cookie", "authorization", "body"}


def test_project_names_are_no_longer_globally_unique(db_session: Session) -> None:
    inspector = inspect(db_session.connection())
    assert "uq_projects_name" not in {
        c["name"] for c in inspector.get_unique_constraints("projects")
    }
    assert any(
        i["name"] == "ix_projects_name" and i["column_names"] == ["name"] and not i["unique"]
        for i in inspector.get_indexes("projects")
    )
    db_session.execute(text("INSERT INTO projects (id, name) VALUES (:a, 'same'), (:b, 'same')"),
                       {"a": uuid.uuid4(), "b": uuid.uuid4()})  # fmt: skip
    # Other project constraints are unchanged.
    rejected(
        db_session,
        "INSERT INTO projects (id, name) VALUES (:i, NULL)",
        {"i": uuid.uuid4()},
        'null value in column "name"',
    )


# --- users --------------------------------------------------------------------------------


def test_user_defaults_and_uuid(db_session: Session) -> None:
    user = make_user(db_session, "alice")
    assert isinstance(user.id, uuid.UUID) and user.id.version == 4
    db_session.refresh(user)
    assert (user.global_role, user.is_active, user.must_change_password) == (
        GlobalRole.USER,
        True,
        False,
    )
    assert user.created_at is not None and user.disabled_at is None


def test_usernames_are_unique_case_insensitively(db_session: Session) -> None:
    make_user(db_session, "Alice")
    rejected(
        db_session,
        "INSERT INTO users (id, username, display_name) VALUES (:i, 'aLICE', 'x')",
        {"i": uuid.uuid4()},
        "uq_users_username_lower",
    )


@pytest.mark.parametrize("name", ["ab", "with space", "bad/slash", "\u00e9mile", ""])
def test_username_format(db_session: Session, name: str) -> None:
    rejected(
        db_session,
        "INSERT INTO users (id, username, display_name) VALUES (:i, :n, 'x')",
        {"i": uuid.uuid4(), "n": name},
        "ck_users_username_format",
    )


def test_username_length_is_limited(db_session: Session) -> None:
    rejected(db_session, "INSERT INTO users (id, username, display_name) VALUES (:i, :n, 'x')",
             {"i": uuid.uuid4(), "n": "a" * 65}, "too long")  # fmt: skip


@pytest.mark.parametrize("role", ["admin", "user"])
def test_valid_global_roles(db_session: Session, role: str) -> None:
    db_session.execute(
        text(
            "INSERT INTO users (id, username, display_name, global_role) VALUES (:i, :u, 'x', :r)"
        ),
        {"i": uuid.uuid4(), "u": f"u-{role}", "r": role},
    )


@pytest.mark.parametrize("role", ["superuser", "root", "ADMIN", "owner", ""])
def test_invalid_global_roles_are_rejected(db_session: Session, role: str) -> None:
    rejected(
        db_session,
        "INSERT INTO users (id, username, display_name, global_role) VALUES (:i, 'bob', 'x', :r)",
        {"i": uuid.uuid4(), "r": role},
        "ck_users_global_role",
    )


def test_disabled_state_is_consistent(db_session: Session) -> None:
    user = make_user(db_session)
    rejected(db_session, "UPDATE users SET is_active = false WHERE id = :i", {"i": user.id},
             "ck_users_disabled_iff_inactive")  # fmt: skip
    rejected(db_session, "UPDATE users SET disabled_at = now() WHERE id = :i", {"i": user.id},
             "ck_users_disabled_iff_inactive")  # fmt: skip
    db_session.execute(
        text("UPDATE users SET is_active = false, disabled_at = now() WHERE id = :i"),
        {"i": user.id},
    )
    db_session.execute(
        text("UPDATE users SET is_active = true, disabled_at = NULL, display_name = 'B' "
             "WHERE id = :i"), {"i": user.id},
    )  # fmt: skip


def test_users_are_never_deleted_and_keep_id_and_username(db_session: Session) -> None:
    user = make_user(db_session, "carol")
    rejected(db_session, "DELETE FROM users WHERE id = :i", {"i": user.id}, "cannot be deleted")
    rejected(db_session, "UPDATE users SET username = 'carol2' WHERE id = :i", {"i": user.id},
             "immutable")  # fmt: skip
    rejected(db_session, "UPDATE users SET id = :n WHERE id = :i",
             {"i": user.id, "n": uuid.uuid4()}, "immutable")  # fmt: skip
    db_session.execute(text("UPDATE users SET global_role = 'admin' WHERE id = :i"), {"i": user.id})


# --- credentials --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["hunter2", "correct horse battery staple", "$2b$12$bcrypt.hash.value", "$argon2i$v=19$x",
     "$argon2id$" + "x" * 600],
)  # fmt: skip
def test_credentials_only_accept_argon2id_hashes(db_session: Session, value: str) -> None:
    user = make_user(db_session)
    rejected(
        db_session,
        "INSERT INTO user_credentials (user_id, password_hash) VALUES (:u, :h)",
        {"u": user.id, "h": value},
        "ck_user_credentials_password_hash_argon2id",
    )


def test_credential_rows(db_session: Session) -> None:
    user = make_user(db_session)
    db_session.execute(
        text("INSERT INTO user_credentials (user_id, password_hash) VALUES (:u, :h)"),
        {"u": user.id, "h": ARGON2_HASH},
    )
    rejected(db_session, "INSERT INTO user_credentials (user_id, password_hash) VALUES (:u, :h)",
             {"u": user.id, "h": ARGON2_HASH}, "pk_user_credentials")  # fmt: skip
    rejected(db_session, "INSERT INTO user_credentials (user_id, password_hash) VALUES (:u, :h)",
             {"u": uuid.uuid4(), "h": ARGON2_HASH},
             "fk_user_credentials_user_id_users")  # fmt: skip
    rejected(db_session, "DELETE FROM user_credentials WHERE user_id = :u", {"u": user.id},
             "cannot be deleted")  # fmt: skip
    rejected(db_session, "UPDATE user_credentials SET user_id = :n WHERE user_id = :u",
             {"u": user.id, "n": make_user(db_session).id}, "permanently")  # fmt: skip
    db_session.execute(
        text("UPDATE user_credentials SET password_hash = :h, password_changed_at = now() "
             "WHERE user_id = :u"), {"u": user.id, "h": ARGON2_HASH + "x"},
    )  # fmt: skip


# --- sessions -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    ["dGhpcy1pcy1hLXJhdy11cmxzYWZlLXRva2VuLW9mLTQzLWNo", "A" * 64, "a" * 63, "g" * 64, ""],
)
def test_sessions_store_only_a_sha256_hex_digest(db_session: Session, token: str) -> None:
    user = make_user(db_session)
    with pytest.raises(DBAPIError, match="ck_sessions_token_sha256_hex"), db_session.begin_nested():
        insert_session(db_session, user, token_sha256=token)


def test_session_expiry_fields(db_session: Session) -> None:
    user = make_user(db_session)
    for idle, expires, match in [
        ("now() + interval '1 hour'", "now() - interval '1 hour'", "ck_sessions_expires_after"),
        ("now() + interval '13 hours'", "now() + interval '12 hours'", "idle_expiry_within"),
        ("now() - interval '1 minute'", "now() + interval '12 hours'", "idle_expiry_within"),
    ]:
        with pytest.raises(DBAPIError, match=match), db_session.begin_nested():
            insert_session(db_session, user, idle=idle, expires=expires)
    sid = insert_session(db_session, user)
    rejected(db_session, "INSERT INTO sessions (id, user_id, token_sha256, idle_expires_at, "
             "expires_at) SELECT :n, user_id, token_sha256, idle_expires_at, expires_at "
             "FROM sessions WHERE id = :s", {"n": uuid.uuid4(), "s": sid},
             "uq_sessions_token_sha256")  # fmt: skip


@pytest.mark.parametrize(
    "assignment",
    [
        "token_sha256 = repeat('b', 64)",
        "user_id = :other",
        "expires_at = expires_at + interval '1 day'",
        "created_at = created_at - interval '1 hour'",
        "user_agent = 'changed'",
        "client_addr = '10.0.0.1'",
    ],
)
def test_session_identity_and_lifetime_are_frozen(db_session: Session, assignment: str) -> None:
    user, other = make_user(db_session), make_user(db_session)
    sid = insert_session(db_session, user)
    rejected(db_session, f"UPDATE sessions SET {assignment} WHERE id = :s",  # noqa: S608
             {"s": sid, "other": other.id}, "immutable")  # fmt: skip


def test_session_activity_revocation_and_pruning(db_session: Session) -> None:
    user = make_user(db_session)
    sid = insert_session(db_session, user)
    db_session.execute(
        text("UPDATE sessions SET last_seen_at = now(), idle_expires_at = idle_expires_at "
             "+ interval '1 minute' WHERE id = :s"), {"s": sid},
    )  # fmt: skip
    rejected(db_session, "UPDATE sessions SET last_seen_at = last_seen_at - interval '1 second' "
             "WHERE id = :s", {"s": sid}, "only moves forward")  # fmt: skip
    rejected(db_session, "UPDATE sessions SET idle_expires_at = idle_expires_at - interval "
             "'2 minutes' WHERE id = :s", {"s": sid}, "only moves forward")  # fmt: skip
    rejected(db_session, "DELETE FROM sessions WHERE id = :s", {"s": sid}, "revoke them first")
    rejected(db_session, "UPDATE sessions SET revoked_at = now() WHERE id = :s", {"s": sid},
             "ck_sessions_revoked_iff_reason")  # fmt: skip
    rejected(db_session, "UPDATE sessions SET revoked_at = now(), revoked_reason = 'expired' "
             "WHERE id = :s", {"s": sid}, "ck_sessions_session_revoked_reason")  # fmt: skip
    db_session.execute(
        text("UPDATE sessions SET revoked_at = now(), revoked_reason = 'logout' WHERE id = :s"),
        {"s": sid},
    )
    # Revocation is final: no un-revoking, no further activity.
    for sql in [
        "UPDATE sessions SET revoked_at = NULL, revoked_reason = NULL WHERE id = :s",
        "UPDATE sessions SET last_seen_at = now() WHERE id = :s",
        "UPDATE sessions SET revoked_reason = 'user_disabled' WHERE id = :s",
    ]:
        rejected(db_session, sql, {"s": sid}, "revoked sessions are final")
    db_session.execute(text("DELETE FROM sessions WHERE id = :s"), {"s": sid})  # pruned
    rejected(db_session, "INSERT INTO sessions (id, user_id, token_sha256, idle_expires_at, "
             "expires_at) VALUES (:i, :u, :t, now() + interval '1 hour', now() + interval "
             "'2 hours')", {"i": uuid.uuid4(), "u": uuid.uuid4(), "t": TOKEN_HASH},
             "fk_sessions_user_id_users")  # fmt: skip


# --- project membership -------------------------------------------------------------------


def test_membership_keys_roles_and_foreign_keys(db_session: Session) -> None:
    project, user = make_project(db_session), make_user(db_session)
    add_member(db_session, project, user, ProjectRole.OWNER)
    deferred_check_passes(db_session)
    sql = "INSERT INTO project_members (project_id, user_id, role) VALUES (:p, :u, :r)"
    rejected(db_session, sql, {"p": project.id, "u": user.id, "r": "viewer"}, "pk_project_members")
    for role in ["admin", "member", "OWNER", ""]:
        rejected(db_session, sql, {"p": project.id, "u": make_user(db_session).id, "r": role},
                 "ck_project_members_project_role")  # fmt: skip
    rejected(db_session, sql, {"p": uuid.uuid4(), "u": user.id, "r": "owner"},
             "fk_project_members_project_id_projects")  # fmt: skip
    rejected(db_session, sql, {"p": project.id, "u": uuid.uuid4(), "r": "owner"},
             "fk_project_members_user_id_users")  # fmt: skip


def test_only_the_role_of_a_membership_changes(db_session: Session) -> None:
    project, owner, other = make_project(db_session), make_user(db_session), make_user(db_session)
    add_member(db_session, project, owner, ProjectRole.OWNER)
    add_member(db_session, project, other, ProjectRole.VIEWER)
    db_session.execute(
        text("UPDATE project_members SET role = 'operator' WHERE user_id = :u"), {"u": other.id}
    )
    for assignment in ["user_id = :x", "project_id = :y", "created_by_user_id = :x",
                       "created_at = now() - interval '1 day'"]:  # fmt: skip
        rejected(db_session, f"UPDATE project_members SET {assignment} WHERE user_id = :u",  # noqa: S608
                 {"u": other.id, "x": make_user(db_session).id, "y": make_project(db_session).id},
                 "only a membership")  # fmt: skip


def test_a_project_with_members_keeps_an_owner(db_session: Session) -> None:
    project, owner, viewer = make_project(db_session), make_user(db_session), make_user(db_session)
    # A first member that is not an owner is refused at commit.
    add_member(db_session, project, viewer, ProjectRole.VIEWER)
    deferred_check_fails(db_session, "at least one owner")
    add_member(db_session, project, owner, ProjectRole.OWNER)
    deferred_check_passes(db_session)
    # Demoting or removing the last owner is refused.
    db_session.execute(text("UPDATE project_members SET role = 'operator' WHERE user_id = :u"),
                       {"u": owner.id})  # fmt: skip
    deferred_check_fails(db_session, "at least one owner")
    db_session.execute(text("UPDATE project_members SET role = 'owner' WHERE user_id = :u"),
                       {"u": owner.id})  # fmt: skip
    db_session.execute(text("DELETE FROM project_members WHERE user_id = :u"), {"u": owner.id})
    deferred_check_fails(db_session, "at least one owner")
    # Handing ownership over within one transaction is allowed.
    db_session.execute(text("UPDATE project_members SET role = 'owner' WHERE user_id = :u"),
                       {"u": viewer.id})  # fmt: skip
    deferred_check_passes(db_session)


def test_a_sole_owner_cannot_leave_the_project_ownerless(db_session: Session) -> None:
    project, owner = make_project(db_session), make_user(db_session)
    add_member(db_session, project, owner, ProjectRole.OWNER)
    deferred_check_passes(db_session)
    db_session.execute(text("DELETE FROM project_members WHERE user_id = :u"), {"u": owner.id})
    deferred_check_fails(db_session, "at least one owner")


def test_legacy_projects_without_members_and_project_deletion(db_session: Session) -> None:
    legacy = make_project(db_session)  # no members: allowed (fail closed, claimed later)
    deferred_check_passes(db_session)
    assert (
        db_session.scalar(
            text("SELECT count(*) FROM project_members WHERE project_id = :p"), {"p": legacy.id}
        )
        == 0
    )
    project, owner = make_project(db_session), make_user(db_session)
    add_member(db_session, project, owner, ProjectRole.OWNER)
    deferred_check_passes(db_session)
    db_session.execute(text("DELETE FROM projects WHERE id = :p"), {"p": project.id})
    deferred_check_passes(db_session)  # memberships cascade with their project
    assert db_session.scalar(text("SELECT count(*) FROM project_members WHERE user_id = :u"),
                             {"u": owner.id}) == 0  # fmt: skip


# --- concurrency: two owners removed at once -----------------------------------------------


@pytest.fixture
def committed(engine: Engine) -> Iterator[Callable[[str, dict[str, Any]], None]]:
    """Commit setup statements for real; remove everything afterwards (users
    cannot be deleted normally, so cleanup bypasses triggers)."""
    created: dict[str, list[Any]] = {"projects": [], "users": []}

    def run(sql: str, params: dict[str, Any]) -> None:
        with engine.begin() as conn:
            conn.execute(text(sql), params)

    run.created = created  # type: ignore[attr-defined]
    yield run
    with engine.begin() as conn:
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(text("DELETE FROM project_members WHERE project_id = ANY(:p)"),
                     {"p": created["projects"]})  # fmt: skip
        conn.execute(text("DELETE FROM projects WHERE id = ANY(:p)"), {"p": created["projects"]})
        conn.execute(text("DELETE FROM users WHERE id = ANY(:u)"), {"u": created["users"]})


@pytest.mark.parametrize("attempt", range(5))
def test_concurrent_removal_of_two_owners_keeps_one(
    engine: Engine, committed: Callable[[str, dict[str, Any]], None], attempt: int
) -> None:
    project, a, b = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    committed.created["projects"].append(project)  # type: ignore[attr-defined]
    committed.created["users"].extend([a, b])  # type: ignore[attr-defined]
    committed("INSERT INTO projects (id, name) VALUES (:p, :n)",
              {"p": project, "n": f"race-{attempt}-{project}"})  # fmt: skip
    for user in (a, b):
        committed("INSERT INTO users (id, username, display_name) VALUES (:u, :n, 'x')",
                  {"u": user, "n": f"race-{user.hex[:16]}"})  # fmt: skip
    committed("INSERT INTO project_members (project_id, user_id, role) VALUES "
              "(:p, :a, 'owner'), (:p, :b, 'owner')", {"p": project, "a": a, "b": b})  # fmt: skip

    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    lock = threading.Lock()

    def remove(user: uuid.UUID) -> None:
        conn = engine.connect()
        try:
            tx = conn.begin()
            conn.execute(text("DELETE FROM project_members WHERE project_id = :p AND user_id = :u"),
                         {"p": project, "u": user})  # fmt: skip
            barrier.wait()  # both deletes done before either commits
            try:
                tx.commit()
                result = "committed"
            except DBAPIError as exc:
                result = "refused" if "at least one owner" in str(exc) else f"error: {exc}"
        finally:
            conn.close()
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=remove, args=(u,)) for u in (a, b)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert sorted(outcomes) == ["committed", "refused"]
    with engine.connect() as conn:
        owners = conn.scalar(
            text("SELECT count(*) FROM project_members WHERE project_id = :p AND role = 'owner'"),
            {"p": project},
        )
    assert owners == 1


# --- audit events ---------------------------------------------------------------------------


def test_audit_events_append_with_database_time(db_session: Session) -> None:
    user, project = make_user(db_session), make_project(db_session)
    eid = insert_audit(
        db_session,
        actor_type="user",
        actor_user_id=user.id,
        action="finding.triaged",
        project_id=project.id,
        resource_type="finding",
        resource_id=uuid.uuid4(),
        metadata='{"to_status": "false_positive", "changed": true, "count": 1, "note": null}',
        occurred_at="2001-01-01T00:00:00Z",  # client-supplied times are ignored
    )
    row = db_session.execute(
        text("SELECT occurred_at > now() - interval '1 minute', actor_user_id, project_id "
             "FROM audit_events WHERE id = :e"), {"e": eid},
    ).one()  # fmt: skip
    assert row == (True, user.id, project.id)
    event = db_session.get(AuditEvent, eid)
    assert event is not None and event.outcome is AuditOutcome.SUCCESS
    assert event.actor_type is AuditActorType.USER


def test_audit_events_cannot_be_changed_or_removed(db_session: Session) -> None:
    eid = insert_audit(db_session)
    rejected(db_session, "UPDATE audit_events SET outcome = 'failure' WHERE id = :e", {"e": eid},
             "append-only")  # fmt: skip
    rejected(db_session, "UPDATE audit_events SET metadata = '{}' WHERE id = :e", {"e": eid},
             "append-only")  # fmt: skip
    rejected(db_session, "DELETE FROM audit_events WHERE id = :e", {"e": eid}, "append-only")
    rejected(db_session, "TRUNCATE audit_events", None, "append-only")


@pytest.mark.parametrize(
    ("metadata", "match"),
    [
        ('{"password": "hunter2"}', "secrets or captured content"),
        ('{"new_password": "x"}', "secrets or captured content"),
        ('{"session_token": "abc"}', "secrets or captured content"),
        ('{"authorization": "Bearer abc"}', "secrets or captured content"),
        ('{"cookie": "sv_session=abc"}', "secrets or captured content"),
        ('{"set_cookie": "a"}', "secrets or captured content"),
        ('{"response_body": "<html>"}', "secrets or captured content"),
        ('{"request_headers": "x"}', "secrets or captured content"),
        ('{"api_key": "k"}', "secrets or captured content"),
        ('{"client_secret": "s"}', "secrets or captured content"),
        ('{"credentials": "c"}', "secrets or captured content"),
        ('{"nested": {"password": "x"}}', "values must be scalars"),
        ('{"list": [1, 2]}', "values must be scalars"),
        ("[1, 2]", "must be a JSON object"),
        ('"text"', "must be a JSON object"),
        ('{"Bad-Key": 1}', "lower_snake_case"),
        ('{"x": "' + "a" * 300 + '"}', "limited to 256"),
        ("{" + ", ".join(f'"k{i}": "{"v" * 200}"' for i in range(30)) + "}", "limited to 4 KB"),
    ],
)
def test_audit_metadata_is_constrained(db_session: Session, metadata: str, match: str) -> None:
    with pytest.raises(DBAPIError, match=match), db_session.begin_nested():
        insert_audit(db_session, metadata=metadata)


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"actor_type": "user"}, "ck_audit_events_user_actor_has_user"),
        ({"actor_type": "system", "actor_user_id": "USER"}, "ck_audit_events_user_actor_has_user"),
        ({"actor_type": "robot"}, "ck_audit_events_audit_actor_type"),
        ({"outcome": "maybe"}, "ck_audit_events_audit_outcome"),
        ({"action": "Scan Launched"}, "ck_audit_events_action_format"),
        ({"action": "scan"}, "ck_audit_events_action_format"),
        ({"resource_type": "scan"}, "ck_audit_events_resource_type_iff_id"),
        ({"resource_id": "RID"}, "ck_audit_events_resource_type_iff_id"),
        ({"resource_type": "Scan!", "resource_id": "RID"}, "ck_audit_events_resource_type_format"),
        ({"actor_type": "user", "actor_user_id": "MISSING"}, "fk_audit_events_actor_user_id_users"),
    ],
)
def test_audit_event_structure(db_session: Session, overrides: dict[str, Any], match: str) -> None:
    user = make_user(db_session)
    resolved = {
        k: (user.id if v == "USER" else uuid.uuid4() if v in ("RID", "MISSING") else v)
        for k, v in overrides.items()
    }
    with pytest.raises(DBAPIError, match=match), db_session.begin_nested():
        insert_audit(db_session, **resolved)


def test_audit_references_outlive_projects(db_session: Session) -> None:
    """project_id/resource_id are historical identifiers, not foreign keys."""
    project = make_project(db_session)
    eid = insert_audit(db_session, project_id=project.id, resource_type="project",
                       resource_id=project.id, action="project.created")  # fmt: skip
    db_session.execute(text("DELETE FROM projects WHERE id = :p"), {"p": project.id})
    assert db_session.scalar(text("SELECT project_id FROM audit_events WHERE id = :e"),
                             {"e": eid}) == project.id  # fmt: skip


# --- platform settings ----------------------------------------------------------------------


def test_platform_settings_is_one_row_with_a_set_once_cutover(db_session: Session) -> None:
    rows = db_session.execute(text("SELECT id, authentication_enforced_at FROM platform_settings"))
    assert rows.all() == [(1, None)]  # authentication is not enforced yet
    rejected(db_session, "INSERT INTO platform_settings (id) VALUES (2)", None,
             "ck_platform_settings_singleton")  # fmt: skip
    rejected(db_session, "INSERT INTO platform_settings (id) VALUES (1)", None,
             "pk_platform_settings")  # fmt: skip
    rejected(db_session, "DELETE FROM platform_settings", None, "cannot be deleted")
    db_session.execute(text("UPDATE platform_settings SET authentication_enforced_at = now()"))
    rejected(db_session, "UPDATE platform_settings SET authentication_enforced_at = NULL", None,
             "recorded once")  # fmt: skip
    rejected(db_session, "UPDATE platform_settings SET authentication_enforced_at = now() "
             "+ interval '1 day'", None, "recorded once")  # fmt: skip


def test_new_models_load(db_session: Session) -> None:
    user = make_user(db_session, global_role=GlobalRole.ADMIN)
    sid = insert_session(db_session, user)
    loaded = db_session.get(UserSession, sid)
    assert loaded is not None and loaded.user_id == user.id and loaded.revoked_at is None
