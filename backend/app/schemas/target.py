import uuid
from datetime import datetime
from typing import Annotated, Self

from pydantic import AfterValidator, AwareDatetime, BaseModel, Field, StrictBool, StringConstraints

from app.models.enums import AuthorizationStatus, TargetEnvironment
from app.models.target import Target
from app.models.target_authorization import TargetAuthorization
from app.schemas.common import DescriptionStr, InputModel, NameStr, PatchModel

HostStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]
PathStr = Annotated[str, StringConstraints(min_length=1, max_length=2048)]
UrlStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)]
Port = Annotated[int, Field(ge=1, le=65535)]

# Fields whose change alters what may be tested; changing any of them requires
# the authorization to be re-acknowledged in the same request.
SCOPE_FIELDS = frozenset(
    {
        "base_url",
        "environment",
        "in_scope_hosts",
        "allowed_ports",
        "in_scope_path_prefixes",
        "excluded_paths",
    }
)


def _must_be_true(value: bool) -> bool:
    if value is not True:
        raise ValueError("must be true to acknowledge the authorization")
    return value


# StrictBool: only JSON `true` counts. Lax validation would also accept 1.
Acknowledgment = Annotated[StrictBool, AfterValidator(_must_be_true)]


class TargetAuthorizationIn(InputModel):
    authorized_by: NameStr = Field(description="Person or organization granting permission.")
    reference: NameStr = Field(description="Ticket, engagement letter or lab name.")
    notes: DescriptionStr | None = None
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    # No acknowledged_by: the authenticated user acknowledging is recorded by the
    # server (Phase 9 M5); a body naming someone is refused as an unknown field.
    acknowledge: Acknowledgment = Field(
        description="Must be true: confirms testing this target's scope is explicitly "
        "authorized by its owner."
    )


class TargetCreate(InputModel):
    name: NameStr
    base_url: UrlStr
    environment: TargetEnvironment
    in_scope_hosts: list[HostStr] = Field(min_length=1, max_length=50)
    allowed_ports: list[Port] | None = Field(
        default=None,
        min_length=1,
        max_length=20,
        description="Defaults to the base_url port only.",
    )
    in_scope_path_prefixes: list[PathStr] = Field(
        default_factory=lambda: ["/"], min_length=1, max_length=50
    )
    excluded_paths: list[PathStr] = Field(default_factory=list, max_length=100)
    authorization: TargetAuthorizationIn


class TargetUpdate(PatchModel):
    """Renaming is a plain update. Any scope change or new `authorization`
    creates a new authorization record; scope changes require one."""

    name: NameStr | None = None
    base_url: UrlStr | None = None
    environment: TargetEnvironment | None = None
    in_scope_hosts: list[HostStr] | None = Field(default=None, min_length=1, max_length=50)
    allowed_ports: list[Port] | None = Field(default=None, min_length=1, max_length=20)
    in_scope_path_prefixes: list[PathStr] | None = Field(default=None, min_length=1, max_length=50)
    excluded_paths: list[PathStr] | None = Field(default=None, max_length=100)
    authorization: TargetAuthorizationIn | None = None


class TargetAuthorizationSummary(BaseModel):
    """The authorization part of a target's current state."""

    id: uuid.UUID
    version: int
    authorized_by: str
    reference: str
    notes: str | None
    valid_from: datetime
    valid_until: datetime
    acknowledged_by: str
    acknowledged_by_user_id: uuid.UUID | None = Field(
        description="The user who acknowledged it; null for records made before Phase 9 M5 "
        "(whose acknowledged_by text is self-asserted)."
    )
    acknowledged_at: datetime
    status: AuthorizationStatus


class TargetRead(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    base_url: str
    environment: TargetEnvironment
    in_scope_hosts: list[str]
    allowed_ports: list[int]
    in_scope_path_prefixes: list[str]
    excluded_paths: list[str]
    authorization: TargetAuthorizationSummary
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, target: Target, status: AuthorizationStatus) -> Self:
        auth = target.current_authorization
        return cls(
            id=target.id,
            project_id=target.project_id,
            name=target.name,
            base_url=auth.base_url,
            environment=auth.environment,
            in_scope_hosts=auth.in_scope_hosts,
            allowed_ports=auth.allowed_ports,
            in_scope_path_prefixes=auth.in_scope_path_prefixes,
            excluded_paths=auth.excluded_paths,
            authorization=TargetAuthorizationSummary(
                id=auth.id,
                version=auth.version,
                authorized_by=auth.authorized_by,
                reference=auth.reference,
                notes=auth.notes,
                valid_from=auth.valid_from,
                valid_until=auth.valid_until,
                acknowledged_by=auth.acknowledged_by,
                acknowledged_by_user_id=auth.acknowledged_by_user_id,
                acknowledged_at=auth.acknowledged_at,
                status=status,
            ),
            created_at=target.created_at,
            updated_at=target.updated_at,
        )


class TargetAuthorizationRead(BaseModel):
    """A full historical authorization record: what was acknowledged, for which scope."""

    id: uuid.UUID
    target_id: uuid.UUID
    version: int
    is_current: bool
    status: AuthorizationStatus
    base_url: str
    environment: TargetEnvironment
    in_scope_hosts: list[str]
    allowed_ports: list[int]
    in_scope_path_prefixes: list[str]
    excluded_paths: list[str]
    authorized_by: str
    reference: str
    notes: str | None
    valid_from: datetime
    valid_until: datetime
    acknowledged_by: str
    acknowledged_by_user_id: uuid.UUID | None = Field(
        description="The user who acknowledged it; null before Phase 9 M5."
    )
    acknowledged_at: datetime
    created_at: datetime

    @classmethod
    def from_model(
        cls, record: TargetAuthorization, *, status: AuthorizationStatus, is_current: bool
    ) -> Self:
        return cls(
            id=record.id,
            target_id=record.target_id,
            version=record.version,
            is_current=is_current,
            status=status,
            base_url=record.base_url,
            environment=record.environment,
            in_scope_hosts=record.in_scope_hosts,
            allowed_ports=record.allowed_ports,
            in_scope_path_prefixes=record.in_scope_path_prefixes,
            excluded_paths=record.excluded_paths,
            authorized_by=record.authorized_by,
            reference=record.reference,
            notes=record.notes,
            valid_from=record.valid_from,
            valid_until=record.valid_until,
            acknowledged_by=record.acknowledged_by,
            acknowledged_by_user_id=record.acknowledged_by_user_id,
            acknowledged_at=record.acknowledged_at,
            created_at=record.created_at,
        )
