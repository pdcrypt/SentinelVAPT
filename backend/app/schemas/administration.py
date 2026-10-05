"""Account and membership administration (Phase 9 M7).

Requests never carry an actor, a project or a credential hash: the actor is
the authenticated user, the project is the authorized path, and passwords are
plaintext inputs hashed by the server (and redacted from 422 responses).
Responses carry identity only: never a password, hash or session token."""

import uuid
from datetime import datetime

from pydantic import Field

from app.models.enums import GlobalRole, ProjectRole
from app.schemas.auth import MAX_PASSWORD_INPUT
from app.schemas.common import InputModel, NameStr, ReadModel


class UserCreate(InputModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]{3,64}$")
    display_name: NameStr
    password: str = Field(
        min_length=1,
        max_length=MAX_PASSWORD_INPUT,
        description="A temporary password; the user must change it at first sign-in.",
    )
    global_role: GlobalRole = GlobalRole.USER


class PasswordReset(InputModel):
    new_password: str = Field(
        min_length=1,
        max_length=MAX_PASSWORD_INPUT,
        description="A temporary password; the user must change it at next sign-in.",
    )


class UserRead(ReadModel):
    id: uuid.UUID
    username: str
    display_name: str
    global_role: GlobalRole
    is_active: bool
    disabled_at: datetime | None
    must_change_password: bool
    last_login_at: datetime | None
    created_at: datetime


class GlobalRoleUpdate(InputModel):
    """The new global role. The account is the one in the path; nothing in the
    body can name another (unknown fields are refused)."""

    global_role: GlobalRole


class MembershipSelfRead(ReadModel):
    """The caller's own relationship to a project: nothing about anyone else.
    Informational for the console; every request is still authorized by the
    API on its own."""

    project_id: uuid.UUID
    user_id: uuid.UUID
    role: ProjectRole


class MemberAdd(InputModel):
    username: str = Field(min_length=1, max_length=64)
    role: ProjectRole


class MemberUpdate(InputModel):
    role: ProjectRole


class MemberRead(ReadModel):
    user_id: uuid.UUID
    username: str
    display_name: str
    role: ProjectRole
    is_active: bool
    created_by_user_id: uuid.UUID | None
    created_at: datetime
