"""Phase 9 M10 migration (e5c9a7b1d3f2) on its own scratch database."""

import uuid
from collections.abc import Iterator

import pytest
from alembic import command
from sqlalchemy import URL, Engine, text
from sqlalchemy.exc import DBAPIError

from app.db.session import make_engine
from tests.integration.conftest import _alembic_config, _test_database_url
from tests.integration.test_identity_migration import _admin_execute
from tests.integration.test_m5_migration import _rows

pytestmark = pytest.mark.integration

M7 = "d2b8e6f3a5c7"
M10 = "e5c9a7b1d3f2"
M10_ACTIONS = {"user.enabled", "user.global_role_changed"}


@pytest.fixture
def scratch() -> Iterator[tuple[URL, Engine]]:
    base = _test_database_url()
    url = base.set(database=f"{base.database}_m10_migration")
    assert (url.database or "").endswith("_test_m10_migration")
    _admin_execute(url, f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)')
    _admin_execute(url, f'CREATE DATABASE "{url.database}"')
    engine = make_engine(url.render_as_string(hide_password=False))
    try:
        yield url, engine
    finally:
        engine.dispose()
        _admin_execute(url, f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)')


def _vocabulary(engine: Engine) -> set[str]:
    with engine.connect() as conn:
        return {a for (a,) in conn.execute(text("SELECT action FROM audit_actions"))}


def _promote(engine: Engine, user: uuid.UUID) -> None:
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET global_role = 'admin' WHERE id = :u"), {"u": user})


def test_upgrade_downgrade_upgrade(scratch: tuple[URL, Engine]) -> None:
    url, engine = scratch
    cfg = _alembic_config(url)
    command.upgrade(cfg, M7)
    admin, disabled = uuid.uuid4(), uuid.uuid4()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (id, username, display_name, global_role) VALUES "
                "(:a, 'root-admin', 'Root', 'admin')"
            ),
            {"a": admin},
        )
        conn.execute(
            text(
                "INSERT INTO users (id, username, display_name, is_active, disabled_at) VALUES "
                "(:d, 'gone-user', 'Gone', false, now())"
            ),
            {"d": disabled},
        )
    with engine.connect() as conn:
        before = _rows(conn)
    command.upgrade(cfg, M10)
    assert _vocabulary(engine) >= M10_ACTIONS
    with engine.connect() as conn:
        after = _rows(conn)
    assert set(after.pop("audit_actions")) > set(before.pop("audit_actions"))
    assert after == before  # no existing row of any other table changed

    # A disabled account cannot become an administrator; an active one can.
    with pytest.raises(DBAPIError, match="cannot become an administrator"):
        _promote(engine, disabled)
    with pytest.raises(DBAPIError, match="cannot become an administrator"), engine.begin() as conn:
        # Not in one statement either (promote and disable together).
        conn.execute(
            text("INSERT INTO users (id, username, display_name) VALUES (:u, 'mixed-user', 'M')"),
            {"u": (mixed := uuid.uuid4())},
        )
        conn.execute(
            text(
                "UPDATE users SET global_role = 'admin', is_active = false, disabled_at = now() "
                "WHERE id = :u"
            ),
            {"u": mixed},
        )
    # The M7 last-administrator rule is unchanged.
    with pytest.raises(DBAPIError, match="active administrator"), engine.begin() as conn:
        conn.execute(text("UPDATE users SET global_role = 'user' WHERE id = :a"), {"a": admin})

    # A recorded M10 action survives a downgrade; the unused one is removed,
    # and so is the trigger. Upgrading again is idempotent.
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_events (id, actor_type, actor_label, action, outcome) "
                "VALUES (gen_random_uuid(), 'system', 'cli', 'user.enabled', 'success')"
            )
        )
    command.downgrade(cfg, M7)
    assert _vocabulary(engine) & M10_ACTIONS == {"user.enabled"}
    _promote(engine, disabled)  # no trigger after the downgrade
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET global_role = 'user' WHERE id = :d"), {"d": disabled})
    command.upgrade(cfg, M10)
    assert _vocabulary(engine) >= M10_ACTIONS
    with pytest.raises(DBAPIError, match="cannot become an administrator"):
        _promote(engine, disabled)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM audit_events")).scalar() == 1
