import pytest
from pydantic import ValidationError

from app.core.config import AppEnv, Settings


def test_database_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_reads_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:secret@db/x")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("CORS_ORIGINS", "http://a.test, http://b.test")

    s = Settings(_env_file=None)

    assert s.app_env is AppEnv.PRODUCTION
    assert s.cors_origins == ["http://a.test", "http://b.test"]


def test_database_url_not_leaked_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:supersecret@db/x")
    s = Settings(_env_file=None)
    assert "supersecret" not in repr(s)
