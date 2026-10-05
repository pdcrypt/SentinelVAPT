"""Phase 9 M6 migration (c4f7a2e9d1b6) on its own scratch database: audit
history written before M6 is kept exactly (no event is rewritten, no actor
or session invented), and upgrade, downgrade and upgrade leave every row of
every table identical."""

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from alembic import command
from sqlalchemy import URL, Engine, text
from sqlalchemy.exc import DBAPIError

from app.db.session import make_engine
from tests.integration.conftest import _alembic_config, _test_database_url
from tests.integration.test_identity_migration import _admin_execute
from tests.integration.test_m5_migration import _rows

pytestmark = pytest.mark.integration

M5 = "b8d2f4a6c1e3"
M6 = "c4f7a2e9d1b6"


@pytest.fixture
def scratch() -> Iterator[tuple[URL, Engine]]:
    base = _test_database_url()
    url = base.set(database=f"{base.database}_m6_migration")
    assert (url.database or "").endswith("_test_m6_migration")
    _admin_execute(url, f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)')
    _admin_execute(url, f'CREATE DATABASE "{url.database}"')
    engine = make_engine(url.render_as_string(hide_password=False))
    try:
        yield url, engine
    finally:
        engine.dispose()
        _admin_execute(url, f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)')


def _seed(engine: Engine) -> dict[str, Any]:
    """Events as M2-M5 wrote them: an anonymous failure, a user's login with
    their session, a server command and a project claim."""
    user, session = uuid.uuid4(), uuid.uuid4()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (id, username, display_name) VALUES (:u, 'early', 'Early User')"
            ),
            {"u": user},
        )
        conn.execute(
            text(
                "INSERT INTO sessions (id, user_id, token_sha256, idle_expires_at, expires_at) "
                "VALUES (:s, :u, :t, now() + interval '30 minutes', now() + interval '1 hour')"
            ),
            {"s": session, "u": user, "t": uuid.uuid4().hex * 2},
        )
        insert = text(
            "INSERT INTO audit_events (id, actor_type, actor_user_id, actor_label, session_id, "
            "action, outcome, resource_type, resource_id, metadata) VALUES (gen_random_uuid(), "
            ":type, :uid, :label, :sid, :action, :outcome, :rtype, :rid, CAST(:md AS jsonb))"
        )
        none: dict[str, Any] = {
            "uid": None,
            "label": None,
            "sid": None,
            "rtype": None,
            "rid": None,
            "md": "{}",
        }
        for event in (
            {
                "type": "anonymous",
                "action": "auth.login_failed",
                "outcome": "failure",
                "rtype": "user",
                "rid": user,
                "md": '{"source": "198.51.100.1", "reason": "bad_password"}',
            },
            {
                "type": "user",
                "uid": user,
                "label": "early",
                "sid": session,
                "action": "auth.login",
                "outcome": "success",
                "rtype": "user",
                "rid": user,
            },
            {
                "type": "system",
                "label": "cli:enforce-authentication",
                "action": "platform.auth_enforced",
                "outcome": "success",
            },
        ):
            conn.execute(insert, {**none, **event})
    return {"user": user, "session": session}


def test_history_is_kept_through_upgrade_and_downgrade(scratch: tuple[URL, Engine]) -> None:
    url, engine = scratch
    cfg = _alembic_config(url)
    command.upgrade(cfg, M5)
    _seed(engine)
    with engine.connect() as conn:
        before = _rows(conn)
    command.upgrade(cfg, M6)
    with engine.connect() as conn:
        after = _rows(conn)
        assert after.pop("audit_actions")  # the vocabulary is the only new table
        assert after == before
        assert conn.execute(text("SELECT count(*) FROM audit_events")).scalar() == 3
    command.downgrade(cfg, M5)
    with engine.connect() as conn:
        assert _rows(conn) == before
    command.upgrade(cfg, M6)
    with engine.connect() as conn:
        again = _rows(conn)
        again.pop("audit_actions")
        assert again == before
        # From now on only the vocabulary can be written.
        with pytest.raises(DBAPIError, match="fk_audit_events_action"):
            conn.execute(
                text(
                    "INSERT INTO audit_events (id, actor_type, actor_label, action, "
                    "outcome) VALUES (gen_random_uuid(), 'system', 'x', 'made.up', "
                    "'success')"
                )
            )
