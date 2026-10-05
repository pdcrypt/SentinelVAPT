"""Phase 9 M5 migration (b8d2f4a6c1e3) on its own scratch database:

- history written before M5 keeps its self-asserted actor text exactly, and
  gets no user id (none is invented);
- upgrade, downgrade and upgrade leave every pre-existing column of every
  row identical, including Phase 5 and Phase 7 report artifacts byte for byte;
- the new actor columns are the only schema change.
"""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from sqlalchemy import URL, Connection, Engine, inspect, text
from sqlalchemy.orm import sessionmaker

from app.db.session import make_engine
from tests.integration.conftest import _alembic_config, _test_database_url
from tests.integration.lab_site import LabSite
from tests.integration.m4_support import build_chain
from tests.integration.scan_support import ScanEnv, lab_actor
from tests.integration.test_identity_migration import _admin_execute

pytestmark = pytest.mark.integration

M1 = "e3a7c1f9b2d4"
M5 = "b8d2f4a6c1e3"
NEW_COLUMNS = {
    "target_authorizations": "acknowledged_by_user_id",
    "assessments": "created_by_user_id",
    "scans": "requested_by_user_id",
    "findings": "status_changed_by_user_id",
    "finding_status_changes": "changed_by_user_id",
    "reports": "requested_by_user_id",
    "retest_reports": "requested_by_user_id",
}


@pytest.fixture
def scratch() -> Iterator[tuple[URL, Engine]]:
    base = _test_database_url()
    url = base.set(database=f"{base.database}_m5_migration")
    assert (url.database or "").endswith("_test_m5_migration")
    _admin_execute(url, f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)')
    _admin_execute(url, f'CREATE DATABASE "{url.database}"')
    engine = make_engine(url.render_as_string(hide_password=False))
    try:
        yield url, engine
    finally:
        engine.dispose()
        _admin_execute(url, f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)')


def _tables(conn: Connection) -> list[str]:
    return sorted(set(inspect(conn).get_table_names()) - {"alembic_version"})


def _rows(conn: Connection) -> dict[str, list[str]]:
    """Every row of every table, without the M5 columns, in a stable order."""
    out = {}
    for table in _tables(conn):
        drop = f" - '{NEW_COLUMNS[table]}'" if table in NEW_COLUMNS else ""
        # Table and column names are constants or come from the catalog.
        sql = f'SELECT (to_jsonb(t){drop})::text AS r FROM "{table}" t ORDER BY 1'  # noqa: S608
        out[table] = [r for (r,) in conn.execute(text(sql))]
    return out


def _artifacts(conn: Connection) -> dict[str, bytes]:
    rows = conn.execute(
        text(
            "SELECT 'report:' || report_id || ':' || format, content FROM report_artifacts "
            "UNION ALL SELECT 'retest:' || report_id || ':' || format, content "
            "FROM retest_report_artifacts"
        )
    )
    return {key: bytes(content) for key, content in rows}


def _seed_history(engine: Engine) -> dict[str, Any]:
    """Pre-M5 data with self-asserted actor text, written as M1-era code did."""
    now = datetime.now(UTC)
    ids = {k: uuid.uuid4() for k in ("project", "target", "auth", "assessment", "scan")}
    with engine.begin() as conn:
        conn.execute(text("SET CONSTRAINTS ALL DEFERRED"))
        # A platform user that existed before M5: nothing may attribute history to them.
        conn.execute(
            text(
                "INSERT INTO users (id, username, display_name) VALUES "
                "(gen_random_uuid(), 'm5-early-user', 'Someone Else')"
            )
        )
        conn.execute(text("INSERT INTO projects (id, name) VALUES (:project, 'Historic')"), ids)
        conn.execute(
            text(
                "INSERT INTO targets (id, project_id, name, current_authorization_id) "
                "VALUES (:target, :project, 'Lab', :auth)"
            ),
            ids,
        )
        conn.execute(
            text(
                "INSERT INTO target_authorizations (id, target_id, version, base_url, environment, "
                "in_scope_hosts, allowed_ports, in_scope_path_prefixes, authorized_by, reference, "
                "valid_from, valid_until, acknowledged_by, acknowledged_at) VALUES (:auth, "
                ":target, 1, 'http://lab/', 'local_lab', ARRAY['lab'], ARRAY[80], ARRAY['/'], "
                "'Owner (stated)', 'R', :f, :u, 'Someone Else (self-asserted)', :f)"
            ),
            {**ids, "f": now - timedelta(days=1), "u": now + timedelta(days=1)},
        )
        conn.execute(
            text(
                "INSERT INTO assessments (id, target_id, authorization_id, name, "
                "status, started_at) VALUES (:assessment, :target, :auth, 'A', "
                "'in_progress', now())"
            ),
            ids,
        )
        conn.execute(
            text(
                "INSERT INTO scans (id, assessment_id, target_id, authorization_id, "
                "config) VALUES (:scan, :assessment, :target, :auth, '{}')"
            ),
            ids,
        )
    return ids


def test_history_is_kept_and_no_actor_is_invented(scratch: tuple[URL, Engine]) -> None:
    url, engine = scratch
    cfg = _alembic_config(url)
    command.upgrade(cfg, M1)
    ids = _seed_history(engine)
    with engine.connect() as conn:
        before = _rows(conn)
    command.upgrade(cfg, M5)
    with engine.connect() as conn:
        assert _rows(conn) == before  # no pre-existing column of any row changed
        for table, column in NEW_COLUMNS.items():
            filled = conn.execute(
                text(
                    f'SELECT count(*) FROM "{table}" WHERE {column} '  # noqa: S608
                    "IS NOT NULL"
                )
            ).scalar()
            assert filled == 0, table  # unknown historical actors stay unknown
        assert (
            conn.execute(
                text("SELECT acknowledged_by FROM target_authorizations WHERE id = :a"),
                {"a": ids["auth"]},
            ).scalar()
            == "Someone Else (self-asserted)"
        )
        # Historical rows stay updatable where they were (the worker updates scans).
        conn.execute(
            text("UPDATE scans SET status = 'cancelled', finished_at = now() WHERE id = :s"),
            {"s": ids["scan"]},
        )
        conn.rollback()
    command.downgrade(cfg, M1)
    with engine.connect() as conn:
        assert _rows(conn) == before
    command.upgrade(cfg, M5)
    with engine.connect() as conn:
        assert _rows(conn) == before


def test_round_trip_keeps_phase_5_and_7_artifacts_byte_identical(
    scratch: tuple[URL, Engine],
) -> None:
    url, engine = scratch
    cfg = _alembic_config(url)
    command.upgrade(cfg, "head")
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    actor = lab_actor(factory)
    with factory() as s:
        project = uuid.uuid4()
        s.execute(text("INSERT INTO projects (id, name) VALUES (:p, 'Chain')"), {"p": project})
        s.commit()
    with LabSite() as site:
        build_chain(ScanEnv(factory, site, project, actor))
    with engine.connect() as conn:
        before_rows, before_artifacts = _rows(conn), _artifacts(conn)
        requested = conn.execute(
            text("SELECT count(*) FROM reports WHERE requested_by_user_id = :u"),
            {"u": actor.user_id},
        ).scalar()
    assert requested == 1 and any(k.startswith("retest:") for k in before_artifacts)
    assert any(k.startswith("report:") for k in before_artifacts)
    command.downgrade(cfg, M1)
    with engine.connect() as conn:
        assert _artifacts(conn) == before_artifacts
        assert _rows(conn) == before_rows
    command.upgrade(cfg, M5)
    with engine.connect() as conn:
        assert _artifacts(conn) == before_artifacts
        assert _rows(conn) == before_rows
        # Re-added columns are empty: the downgrade lost them, and nothing is guessed.
        assert (
            conn.execute(
                text("SELECT count(*) FROM reports WHERE requested_by_user_id IS NOT NULL")
            ).scalar()
            == 0
        )
