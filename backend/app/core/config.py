"""Application settings, loaded from environment variables only.

Secrets have no defaults: if a required value is missing the app fails at
startup instead of silently running with an insecure fallback.

For local development, values are also read from the repo-root `.env` (the
same file docker compose uses). Real environment variables take precedence.
Inside the container that path does not exist and is simply skipped.
"""

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class AppEnv(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


# backend/app/core/config.py -> repo root
ROOT_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT_ENV_FILE, extra="ignore")

    app_env: AppEnv = AppEnv.DEVELOPMENT
    log_level: str = "INFO"

    # Required. Contains a password, so it is kept as a SecretStr to avoid
    # leaking it in logs or reprs.
    database_url: SecretStr

    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Scan worker (python -m app.worker). WORKER_ID defaults to host:pid.
    worker_id: str | None = None
    worker_poll_seconds: float = Field(default=2.0, gt=0, le=60)
    worker_heartbeat_seconds: float = Field(default=5.0, gt=0, le=60)
    worker_stale_after_seconds: float = Field(default=60.0, gt=0, le=3600)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment
