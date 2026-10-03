import uuid
from datetime import datetime
from typing import Any

from pydantic import Field, StrictBool, computed_field

from app.models.enums import ScanStatus
from app.schemas.common import InputModel, ReadModel


class ScanCreate(InputModel):
    allow_untrusted_tls: StrictBool = Field(
        default=False,
        description="Accept self-signed/untrusted TLS certificates on the lab target. "
        "Gives up protection against impersonation of the target; see "
        "docs/checks/discovery.md. Limits cannot be overridden.",
    )


class ScanRead(ReadModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    target_id: uuid.UUID
    authorization_id: uuid.UUID
    status: ScanStatus
    stop_reason: str | None
    cancel_requested_at: datetime | None
    cancel_reason: str | None
    started_at: datetime | None
    finished_at: datetime | None
    heartbeat_at: datetime | None
    error_code: str | None
    error_message: str | None
    scanner_version: str | None
    config: dict[str, Any]
    grant_snapshot: dict[str, Any] | None = Field(
        description="Audit record of the grant the scanner was given. Not authorization state."
    )
    requests_sent: int
    pages_count: int
    endpoints_count: int
    events_count: int
    evidence_count: int
    created_at: datetime
    updated_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cancel_requested(self) -> bool:
        return self.cancel_requested_at is not None


class ScanLogRead(ReadModel):
    sequence: int
    at: datetime
    level: str
    code: str
    message: str
    url: str | None
    data: dict[str, Any] | None


class AssetRead(ReadModel):
    id: uuid.UUID
    scheme: str
    host: str
    port: int
    ip_addresses: list[str]


class CookieRead(ReadModel):
    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    domain: str | None
    path: str | None
    has_expiry: bool


class EndpointRead(ReadModel):
    id: uuid.UUID
    asset_id: uuid.UUID | None
    fingerprint: str
    method: str
    url: str
    source: str
    found_on: str | None
    fetched: bool
    skip_reason: str | None
    query_param_names: list[str]
    depth: int | None
    status_code: int | None
    content_type: str | None
    declared_length: int | None
    body_bytes: int | None
    truncated: bool | None
    elapsed_ms: int | None
    title: str | None
    redirect_location: str | None
    allowed_methods: list[str] | None
    tech_hints: list[dict[str, Any]]
    cookies: list[CookieRead] = Field(default_factory=list)


class EvidenceRead(ReadModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    endpoint_id: uuid.UUID | None
    method: str
    url: str
    request_headers: list[list[str]]
    status_code: int
    response_headers: list[list[str]]
    body_excerpt: str
    body_sha256: str
    body_bytes_captured: int
    truncated: bool
    peer: str
    redactions: list[str]
    created_at: datetime
