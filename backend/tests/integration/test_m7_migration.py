"""Phase 9 M7 migration (d2b8e6f3a5c7) on its own scratch database."""

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

M6 = "c4f7a2e9d1b6"
M7 = "d2b8e6f3a5c7"
M7_ACTIONS = {
    "user.password_reset",
    "user.change_refused",
    "membership.added",
    "membership.role_changed",
    "membership.removed",
    "membership.change_refused",
}


@pytest.fixture
def scratch() -> Iterator[tuple[URL, Engine]]:
    base = _test_database_url()
    url = base.set(database=f"{base.database}_m7_migration")
    assert (url.database or "").endswith("_test_m7_migration")
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


def test_upgrade_downgrade_keeps_history_and_the_vocabulary_in_use(
    scratch: tuple[URL, Engine],
) -> None:
    url, engine = scratch
    cfg = _alembic_config(url)
    command.upgrade(cfg, M6)
    admin = uuid.uuid4()
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
                "INSERT INTO audit_events (id, actor_type, actor_label, action, outcome) "
                "VALUES (gen_random_uuid(), 'system', 'cli', 'user.created', 'success')"
            )
        )
    with engine.connect() as conn:
        before = _rows(conn)
    command.upgrade(cfg, M7)
    assert _vocabulary(engine) >= M7_ACTIONS
    with engine.connect() as conn:
        after = _rows(conn)
    assert set(after.pop("audit_actions")) > set(before.pop("audit_actions"))
    assert after == before  # no existing row of any other table changed
    # The platform keeps an active administrator.
    with pytest.raises(DBAPIError, match="active administrator"), engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET is_active = false, disabled_at = now() WHERE id = :a"),
            {"a": admin},
        )
    # A recorded M7 action survives a downgrade (its events keep their key);
    # the unused ones are removed; upgrading again is idempotent.
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_events (id, actor_type, actor_label, action, outcome) "
                "VALUES (gen_random_uuid(), 'system', 'cli', 'membership.added', "
                "'success')"
            )
        )
    command.downgrade(cfg, M6)
    assert _vocabulary(engine) & M7_ACTIONS == {"membership.added"}
    with engine.begin() as conn:  # no trigger after the downgrade
        conn.execute(
            text("UPDATE users SET is_active = false, disabled_at = now() WHERE id = :a"),
            {"a": admin},
        )
        conn.execute(
            text("UPDATE users SET is_active = true, disabled_at = NULL WHERE id = :a"),
            {"a": admin},
        )
    command.upgrade(cfg, M7)
    assert _vocabulary(engine) >= M7_ACTIONS
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM audit_events")).scalar() == 2
