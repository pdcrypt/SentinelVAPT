"""Engine and session wiring.

create_app() builds one engine and session factory from the Settings it is
given and stores them on app.state, so the app and its tests always agree on
which database is used. Dependencies read them from there.
"""

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker


def make_engine(database_url: str) -> Engine:
    return create_engine(database_url, pool_pre_ping=True)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def get_engine(request: Request) -> Engine:
    engine: Engine = request.app.state.engine
    return engine


def get_session(request: Request) -> Iterator[Session]:
    """FastAPI dependency: one session per request. Uncommitted work is rolled
    back when the session closes."""
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session:
        yield session


def ping(engine: Engine) -> None:
    """Raise if the database is unreachable."""
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
