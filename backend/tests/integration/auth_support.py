"""Fixtures for the Phase 9 M2 authentication tests.

Authentication commits (failed logins are recorded and committed: they are
the throttling record) and throttling uses database time, so these tests run
against the test database with real commits instead of a rolled-back
savepoint. Everything they create is removed afterwards; users, credentials,
sessions and audit events cannot be deleted normally, so cleanup bypasses the
triggers (session_replication_role = replica), as other committed-data tests do.
"""

import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.api.deps import get_clock
from app.core.config import Settings
from app.core.passwords import Argon2Parameters, Passwords
from app.db.session import get_session
from app.main import create_app
from app.models import User, UserCredential
from app.models.enums import GlobalRole
from tests.integration.conftest import FrozenClock

PREFIX = "m2-"
PASSWORD = "lab-password-1234"  # noqa: S105  # test fixture
FLOOR = Argon2Parameters(time_cost=2, memory_kib=19456, parallelism=1)


def auth_settings(settings: Settings, **overrides: Any) -> Settings:
    """Argon2 at the security floor (fast tests) and short throttle windows."""
    values: dict[str, Any] = {
        "auth_argon2_time_cost": FLOOR.time_cost,
        "auth_argon2_memory_kib": FLOOR.memory_kib,
        "auth_argon2_parallelism": FLOOR.parallelism,
        "auth_throttle_window_seconds": 30.0,
        "auth_throttle_account_threshold": 3,
        "auth_throttle_account_base_delay_seconds": 0.4,
        "auth_throttle_account_max_delay_seconds": 1.2,
        "auth_throttle_source_threshold": 1000,
    }
    values.update(overrides)
    return settings.model_copy(update=values)


@dataclass
class Live:
    engine: Engine
    factory: sessionmaker[Session]
    settings: Settings
    clock: FrozenClock
    passwords: Passwords = field(default_factory=lambda: Passwords(FLOOR))
    clients: list[TestClient] = field(default_factory=list)

    def client(self, source: str = "198.51.100.7", **overrides: Any) -> TestClient:
        """An API client whose requests come from `source` and commit."""
        app = create_app(self.settings.model_copy(update=overrides) if overrides else self.settings)

        def session() -> Iterator[Session]:
            with self.factory() as s:
                yield s

        app.dependency_overrides[get_session] = session
        app.dependency_overrides[get_clock] = lambda: self.clock
        client = TestClient(app, client=(source, 50000))
        client.__enter__()
        self.clients.append(client)
        return client

    def user(
        self,
        name: str | None = None,
        password: str = PASSWORD,
        *,
        role: GlobalRole = GlobalRole.USER,
        active: bool = True,
        params: Argon2Parameters | None = None,
    ) -> User:
        username = f"{PREFIX}{name or uuid.uuid4().hex[:10]}"
        hasher = Passwords(params) if params is not None else self.passwords
        with self.factory() as s:
            user = User(username=username, display_name=f"Test {username}", global_role=role)
            s.add(user)
            s.flush()
            if not active:
                user.is_active = False
                user.disabled_at = self.clock()
            s.add(UserCredential(user_id=user.id, password_hash=hasher.hash(password)))
            s.commit()
            s.refresh(user)
            s.expunge(user)
        return user

    def scalar(self, sql: str, **params: Any) -> Any:
        with self.engine.connect() as conn:
            return conn.execute(text(sql), params).scalar()

    def rows(self, sql: str, **params: Any) -> list[Any]:
        with self.engine.connect() as conn:
            return list(conn.execute(text(sql), params).all())

    def advance(self, **delta: float) -> None:
        self.clock.advance(timedelta(**delta))


def _cleanup(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        users = f"SELECT id FROM users WHERE username LIKE '{PREFIX}%'"  # noqa: S608  # constant
        conn.execute(text(f"DELETE FROM audit_events WHERE actor_user_id IN ({users}) "  # noqa: S608
                          f"OR resource_id IN ({users}) OR metadata ->> 'source' LIKE 'm2-%' "
                          "OR metadata ->> 'source' LIKE '198.51.100.%' "
                          "OR metadata ->> 'source' IN ('testclient', 'cli')"))  # fmt: skip
        conn.execute(text(f"DELETE FROM sessions WHERE user_id IN ({users})"))  # noqa: S608
        conn.execute(text(f"DELETE FROM user_credentials WHERE user_id IN ({users})"))  # noqa: S608
        conn.execute(text(f"DELETE FROM users WHERE id IN ({users})"))  # noqa: S608


@pytest.fixture
def live(engine: Engine, settings: Settings, clock: FrozenClock) -> Iterator[Live]:
    _cleanup(engine)
    env = Live(engine, sessionmaker(bind=engine, expire_on_commit=False),
               auth_settings(settings), clock)  # fmt: skip
    try:
        yield env
    finally:
        for client in env.clients:
            client.__exit__(None, None, None)
        _cleanup(engine)


def login(client: TestClient, username: str, password: str = PASSWORD, **kw: Any) -> Any:
    return client.post("/api/v1/auth/login", json={"username": username, "password": password},
                       **kw)  # fmt: skip


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


Requester = Callable[..., Any]
