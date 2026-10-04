import os
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.config import AppEnv, Settings
from app.main import create_app


def _pdf_available() -> bool:
    from sentinel_reports import PdfUnavailable
    from sentinel_reports.pdf import pdf_renderer_name

    try:
        pdf_renderer_name()
    except PdfUnavailable:
        return False
    return True


PDF_AVAILABLE = _pdf_available()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Tests marked `pdf` need WeasyPrint's system libraries (Pango). Locally
    they are skipped if those are missing; in CI and the Docker test run they
    must run."""
    if PDF_AVAILABLE:
        return
    if os.environ.get("CI") or os.environ.get("REQUIRE_PDF"):
        raise pytest.UsageError("WeasyPrint system libraries are required (CI / REQUIRE_PDF)")
    skip = pytest.mark.skip(reason="WeasyPrint system libraries not installed")
    for item in items:
        if "pdf" in item.keywords:
            item.add_marker(skip)


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
