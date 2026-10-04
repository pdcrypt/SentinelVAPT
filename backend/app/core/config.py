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
from typing import Annotated, Literal

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
    # Role of `python -m app.worker` when --role is not given (ADR 0010).
    worker_role: Literal["scans", "reports", "all"] = "all"
    # A report still generating after this long is failed as worker_lost.
    worker_report_stale_after_seconds: float = Field(default=600.0, gt=0, le=86400)

    # --- Authentication (ADR 0014, Phase 9 M2) ---------------------------------------
    # Server-side sessions: idle expiry moves with activity; the absolute
    # lifetime is fixed at login. Bounds are hard maxima.
    auth_session_idle_minutes: int = Field(default=30, ge=5, le=120)
    auth_session_absolute_hours: int = Field(default=12, ge=1, le=24)
    # Argon2id. Defaults are RFC 9106's second recommendation (argon2-cffi's
    # defaults); the lower bounds are the OWASP minimum (m=19 MiB, t=2, p=1),
    # so configuration can never weaken hashing below it.
    auth_argon2_time_cost: int = Field(default=3, ge=2, le=10)
    auth_argon2_memory_kib: int = Field(default=65536, ge=19456, le=1048576)
    auth_argon2_parallelism: int = Field(default=4, ge=1, le=16)
    # Login throttling (counted from audit_events, no lockout state).
    # Per account: from the threshold-th failure since the last successful
    # login (within the window), each attempt must wait base * 2^(n - threshold)
    # seconds after the latest failure, capped at the maximum.
    auth_throttle_window_seconds: float = Field(default=900.0, gt=0, le=86400)
    auth_throttle_account_threshold: int = Field(default=5, ge=1, le=100)
    auth_throttle_account_base_delay_seconds: float = Field(default=1.0, gt=0, le=60)
    auth_throttle_account_max_delay_seconds: float = Field(default=900.0, gt=0, le=3600)
    # Per source: failures from one address within the window.
    auth_throttle_source_threshold: int = Field(default=50, ge=1, le=100000)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment
