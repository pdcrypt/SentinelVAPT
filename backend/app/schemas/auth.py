import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.models.enums import GlobalRole
from app.schemas.common import InputModel

# Generous request bounds: they only cap the work an oversized request can
# cause. The password policy (app/core/passwords.py) applies to new passwords.
MAX_LOGIN_USERNAME = 256
MAX_PASSWORD_INPUT = 1024


class LoginRequest(InputModel):
    username: str = Field(min_length=1, max_length=MAX_LOGIN_USERNAME)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_INPUT)


class PasswordChangeRequest(InputModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_INPUT)
    new_password: str = Field(min_length=1, max_length=MAX_PASSWORD_INPUT)


class CurrentUser(BaseModel):
    id: uuid.UUID
    username: str
    display_name: str
    global_role: GlobalRole
    must_change_password: bool


class SessionInfo(BaseModel):
    created_at: datetime
    idle_expires_at: datetime
    expires_at: datetime


class MeResponse(BaseModel):
    """The authenticated platform user. Says nothing about project access."""

    user: CurrentUser
    session: SessionInfo


class SessionResponse(MeResponse):
    """Returned by login and password change only. `token` is the only copy of
    the opaque session token: the server keeps just its SHA-256. It is meant
    for the Next.js server, which keeps it in an HttpOnly cookie (M8)."""

    token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105  # the scheme name, not a secret
