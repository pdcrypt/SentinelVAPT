"""Phase 9 M1 migration (e3a7c1f9b2d4) against a database that already holds
Phase 1-8 data: upgrade, downgrade and upgrade again leave every existing row
byte-identical, add no users or memberships, and change no existing trigger
or constraint except the obsolete uq_projects_name.

Runs on its own scratch database so the shared test database is untouched."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import URL, Connection, Engine, inspect, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.db.session import get_session, make_engine
from app.main import create_app
from tests.integration.conftest import _alembic_config, _test_database_url

pytestmark = pytest.mark.integration

PREVIOUS = "9d4b6e2f1a83"
M1 = "e3a7c1f9b2d4"
NEW_TABLES = {
    "users",
    "user_credentials",
    "sessions",
    "project_members",
    "audit_events",
    "platform_settings",
}


def _admin_execute(url: URL, sql: str) -> None:
    admin = make_engine(url.set(database="postgres").render_as_string(hide_password=False))
    try:
        with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text(sql))
    finally:
        admin.dispose()


@pytest.fixture
def scratch() -> Iterator[tuple[URL, Engine]]:
    base = _test_database_url()
    url = base.set(database=f"{base.database}_m1_migration")
    assert (url.database or "").endswith("_test_m1_migration")
    _admin_execute(url, f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)')
    _admin_execute(url, f'CREATE DATABASE "{url.database}"')
    engine = make_engine(url.render_as_string(hide_password=False))
    try:
        yield url, engine
    finally:
        engine.dispose()
        _admin_execute(url, f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)')


def _seed(engine: Engine, settings: Settings) -> None:
    """Representative Phase 1-3 data through the real API: projects, a target
    with two authorization versions (self-asserted actor text), an assessment
    and a queued scan."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    app = create_app(settings)

    def session() -> Iterator[Session]:
        with factory() as s:
            yield s

    app.dependency_overrides[get_session] = session
    now = datetime.now(UTC)
    authorization: dict[str, Any] = {
        "authorized_by": "Lab Owner \u00e9\u202e",
        "reference": "LAB-001",
        "notes": "historical self-asserted text \u0007",
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=30)).isoformat(),
        "acknowledged_by": "Student Tester (self-asserted)",
        "acknowledge": True,
    }
    with TestClient(app) as api:
        project = api.post("/api/v1/projects", json={"name": "Legacy lab"}).json()
        api.post("/api/v1/projects", json={"name": "Second legacy project", "description": "x"})
        target = api.post(
            f"/api/v1/projects/{project['id']}/targets",
            json={
                "name": "Lab target",
                "base_url": "http://lab-target/",
                "environment": "local_lab",
                "in_scope_hosts": ["lab-target"],
                "authorization": authorization,
            },
        )
        assert target.status_code == 201, target.text
        target_id = target.json()["id"]
        reauthorized = api.patch(
            f"/api/v1/targets/{target_id}",
            json={"authorization": {**authorization, "reference": "LAB-002"}},
        )
        assert reauthorized.status_code == 200, reauthorized.text
        assessment = api.post(
            f"/api/v1/targets/{target_id}/assessments", json={"name": "Baseline"}
        ).json()
        assert api.post(f"/api/v1/assessments/{assessment['id']}/start").status_code == 200
        scan = api.post(f"/api/v1/assessments/{assessment['id']}/scans", json={})
        assert scan.status_code == 201, scan.text


def _tables(conn: Connection) -> set[str]:
    return set(inspect(conn).get_table_names()) - {"alembic_version"}


def _checksums(conn: Connection, tables: set[str]) -> dict[str, tuple[int, str]]:
    """Row count and an order-independent digest of every row of each table."""
    digest = "md5(coalesce(string_agg(t::text, '|' ORDER BY t::text), ''))"
    out = {}
    for table in sorted(tables):
        # Table names come from the database catalog, not from input.
        sql = f'SELECT count(*), {digest} FROM "{table}" t'  # noqa: S608
        count, rows = conn.execute(text(sql)).one()
        out[table] = (count, rows)
    return out


def _signature(conn: Connection, tables: set[str]) -> dict[str, set[str]]:
    """Triggers, constraints and indexes of the given tables."""
    params = {"tables": sorted(tables)}
    triggers = conn.execute(
        text(
            "SELECT c.relname || ':' || t.tgname || ':' || md5(pg_get_triggerdef(t.oid)) "
            "FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
            "WHERE NOT t.tgisinternal AND c.relname = ANY(:tables)"
        ),
        params,
    ).scalars()
    constraints = conn.execute(
        text(
            "SELECT c.relname || ':' || k.conname || ':' || md5(pg_get_constraintdef(k.oid)) "
            "FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid "
            "WHERE c.relname = ANY(:tables)"
        ),
        params,
    ).scalars()
    indexes = conn.execute(
        text(
            "SELECT tablename || ':' || indexname || ':' || md5(indexdef) FROM pg_indexes "
            "WHERE schemaname = 'public' AND tablename = ANY(:tables)"
        ),
        params,
    ).scalars()
    functions = conn.execute(
        text(
            "SELECT p.proname || ':' || md5(pg_get_functiondef(p.oid)) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'"
        )
    ).scalars()
    return {
        "triggers": set(triggers),
        "constraints": set(constraints),
        "indexes": set(indexes),
        "functions": set(functions),
    }


def test_round_trip_preserves_phase_1_to_8_data(
    scratch: tuple[URL, Engine], settings: Settings
) -> None:
    url, engine = scratch
    cfg = _alembic_config(url)
    command.upgrade(cfg, PREVIOUS)
    _seed(engine, settings)

    with engine.connect() as conn:
        existing = _tables(conn)
        assert not existing & NEW_TABLES
        data_before = _checksums(conn, existing)
        signature_before = _signature(conn, existing)
    assert data_before["projects"][0] == 2
    assert data_before["target_authorizations"][0] == 2
    assert data_before["scans"][0] == 1

    command.upgrade(cfg, M1)
    with engine.connect() as conn:
        assert _tables(conn) == existing | NEW_TABLES
        assert _checksums(conn, existing) == data_before  # no existing row changed
        for table in NEW_TABLES - {"platform_settings"}:
            assert conn.scalar(text(f'SELECT count(*) FROM "{table}"')) == 0, table  # noqa: S608
        assert conn.execute(
            text("SELECT id, authentication_enforced_at FROM platform_settings")
        ).all() == [(1, None)]
        after = _signature(conn, existing)
    # Existing triggers are untouched; only uq_projects_name -> ix_projects_name.
    assert after["triggers"] == signature_before["triggers"]
    removed = signature_before["constraints"] - after["constraints"]
    assert {c.rsplit(":", 1)[0] for c in removed} == {"projects:uq_projects_name"}
    assert after["constraints"] <= signature_before["constraints"]
    added_indexes = after["indexes"] - signature_before["indexes"]
    assert {i.rsplit(":", 1)[0] for i in added_indexes} == {"projects:ix_projects_name"}
    assert {i.rsplit(":", 1)[0] for i in signature_before["indexes"] - after["indexes"]} == {
        "projects:uq_projects_name"
    }
    assert signature_before["functions"] <= after["functions"]  # none replaced

    command.downgrade(cfg, PREVIOUS)
    with engine.connect() as conn:
        assert _tables(conn) == existing
        assert _checksums(conn, existing) == data_before
        assert _signature(conn, existing) == signature_before  # restored exactly

    command.upgrade(cfg, M1)
    with engine.connect() as conn:
        assert _checksums(conn, existing) == data_before


def test_downgrade_refuses_duplicate_project_names(scratch: tuple[URL, Engine]) -> None:
    url, engine = scratch
    cfg = _alembic_config(url)
    command.upgrade(cfg, M1)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO projects (id, name) VALUES (gen_random_uuid(), 'dup'), "
                "(gen_random_uuid(), 'dup')"
            )
        )
    with pytest.raises(DBAPIError, match="duplicate project names exist"):
        command.downgrade(cfg, PREVIOUS)
    with engine.connect() as conn:  # the failed downgrade changed nothing
        assert conn.scalar(text("SELECT version_num FROM alembic_version")) == M1
        assert conn.scalar(text("SELECT count(*) FROM projects WHERE name = 'dup'")) == 2
