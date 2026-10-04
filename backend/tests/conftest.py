from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.config import AppEnv, Settings
from app.main import create_app


@pytest.fixture
def settings() -> Settings:
    return Settings(
        app_env=AppEnv.TEST,
        database_url=SecretStr("postgresql+psycopg://test:test@localhost:5432/test"),
        cors_origins=["http://localhost:3000"],
    )


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return create_app(settings)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c
