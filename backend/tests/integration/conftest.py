"""PostgreSQL-backed fixtures.

Integration tests use a dedicated database whose name must end in `_test`:
- TEST_DATABASE_URL if set (CI), otherwise
- DATABASE_URL (from the environment or the repo-root .env) with `_test` appended.

The schema is built by running the real Alembic migrations (including a full
downgrade/upgrade round trip).

Isolation mirrors production:
- Each test runs on one connection inside an outer transaction that is rolled
  back afterwards, so tests never see each other's data.
- Each API request gets its *own* Session (as get_session does in production),
  running in a SAVEPOINT on that connection. A request that commits releases
  its savepoint; a request that fails is rolled back to it, so a failed request
  cannot leak changes into later requests.
- Deferred constraints are normally checked at COMMIT, which never happens
  here; they are forced to be checked whenever a request's session commits.

Since Phase 9 M4 every product route requires an authenticated principal and
project membership. The `api` client acts as a real user (created inside the
rolled-back transaction) through a dependency override of get_principal; it
owns every project it creates through the API, as any creator does. The
authentication and authorization suites (test_auth*, test_authz*,
test_m4_*) never use this override: they log in for real.
"""

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import URL, Connection, Engine, event, make_url, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.api.deps import get_clock, get_principal
from app.core.config import Settings, get_settings
from app.db.session import get_session, make_engine
from app.main import create_app
from app.models import User
from app.models.enums import GlobalRole
from app.services.auth import Principal

BACKEND_DIR = Path(__file__).resolve().parents[2]


def _test_database_url() -> URL:
    explicit = os.environ.get("TEST_DATABASE_URL")
    if explicit:
        url = make_url(explicit)
    else:
        base = make_url(get_settings().database_url.get_secret_value())
        url = base.set(database=f"{base.database}_test")
    if not (url.database or "").endswith("_test"):
        raise pytest.UsageError(
            f"Refusing to run integration tests against '{url.database}': "
            "the test database name must end in '_test'."
        )
    return url


def _ensure_database(url: URL) -> None:
    admin = make_engine(url.set(database="postgres").render_as_string(hide_password=False))
    try:
        with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            exists = conn.scalar(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": url.database}
            )
            if not exists:
                quoted = conn.dialect.identifier_preparer.quote(url.database or "")
                conn.execute(text(f"CREATE DATABASE {quoted}"))
    finally:
        admin.dispose()


def _alembic_config(url: URL) -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    cfg.attributes["database_url"] = url.render_as_string(hide_password=False)
    cfg.attributes["configure_logger"] = False
    return cfg


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    url = _test_database_url()
    try:
        _ensure_database(url)
    except OperationalError as exc:
        if os.environ.get("CI"):
            raise
        pytest.skip(f"PostgreSQL not reachable ({exc.orig}); run: docker compose up -d db")

    engine = make_engine(url.render_as_string(hide_password=False))
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))

    cfg = _alembic_config(url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")

    yield engine
    engine.dispose()


def _check_deferred_constraints(session: Session) -> None:
    # What a real COMMIT would do: check DEFERRABLE INITIALLY DEFERRED constraints
    # (e.g. targets.current_authorization_id) now, then restore deferral.
    session.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
    session.execute(text("SET CONSTRAINTS ALL DEFERRED"))


def open_session(conn: Connection) -> Session:
    """A session confined to a SAVEPOINT on the test connection."""
    session = Session(bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False)
    event.listen(session, "before_commit", _check_deferred_constraints)
    return session


@pytest.fixture
def db_connection(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as conn:
        outer = conn.begin()
        try:
            yield conn
        finally:
            outer.rollback()


@pytest.fixture
def db_session(db_connection: Connection) -> Iterator[Session]:
    with open_session(db_connection) as session:
        yield session


class FrozenClock:
    """Controllable clock injected into services in place of utc_now."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(NOW)


def principal_for(user: User) -> Principal:
    """A principal for `user` without a session row (tests overriding
    get_principal only; the authentication suites log in for real)."""
    return Principal(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        global_role=GlobalRole(user.global_role),
        must_change_password=False,
        session_id=uuid.uuid4(),
        session_created_at=NOW,
        idle_expires_at=NOW + timedelta(minutes=30),
        expires_at=NOW + timedelta(hours=12),
    )


@pytest.fixture
def api_user(db_connection: Connection) -> User:
    with open_session(db_connection) as session:
        user = User(username=f"api-{uuid.uuid4().hex[:12]}", display_name="API Tester")
        session.add(user)
        session.commit()
        session.expunge(user)
    return user


@pytest.fixture
def api(
    settings: Settings, db_connection: Connection, clock: FrozenClock, api_user: User
) -> Iterator[TestClient]:
    app = create_app(settings)
    app.dependency_overrides[get_principal] = lambda: principal_for(api_user)

    def request_session() -> Iterator[Session]:
        # A fresh session per request; closing it without commit rolls back.
        with open_session(db_connection) as session:
            yield session

    app.dependency_overrides[get_session] = request_session
    app.dependency_overrides[get_clock] = lambda: clock
    with TestClient(app) as client:
        yield client


# --- Payload helpers ------------------------------------------------------------


def authorization_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "authorized_by": "Lab Owner",
        "reference": "LAB-001",
        "notes": "Local Docker lab",
        "valid_from": (NOW - timedelta(days=1)).isoformat(),
        "valid_until": (NOW + timedelta(days=30)).isoformat(),
        "acknowledged_by": "Student Tester",
        "acknowledge": True,
    }
    payload.update(overrides)
    return payload


def target_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": "Juice Shop",
        "base_url": "http://juice-shop:3000/",
        "environment": "local_lab",
        "in_scope_hosts": ["juice-shop"],
        "authorization": authorization_payload(),
    }
    payload.update(overrides)
    return payload


def create_project(api: TestClient, name: str = "Lab project") -> dict[str, Any]:
    resp = api.post("/api/v1/projects", json={"name": name})
    assert resp.status_code == 201, resp.text
    body: dict[str, Any] = resp.json()
    return body


def create_target(api: TestClient, project_id: str, **overrides: Any) -> dict[str, Any]:
    resp = api.post(f"/api/v1/projects/{project_id}/targets", json=target_payload(**overrides))
    assert resp.status_code == 201, resp.text
    body: dict[str, Any] = resp.json()
    return body


def create_assessment(api: TestClient, target_id: str, name: str = "Baseline") -> dict[str, Any]:
    resp = api.post(f"/api/v1/targets/{target_id}/assessments", json={"name": name})
    assert resp.status_code == 201, resp.text
    body: dict[str, Any] = resp.json()
    return body


# Phase 3: committed-data fixtures for scan/worker tests.
from tests.integration.scan_support import scan_env  # noqa: E402, F401
