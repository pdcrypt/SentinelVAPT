"""Structured discovery results, designed to be persisted in Phase 3.

Plain dataclasses with to_dict() producing JSON-safe values. Every URL, header
and excerpt in here has already been redacted.
"""

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = 1


class StopReason(StrEnum):
    COMPLETED = "completed"
    REQUEST_LIMIT = "request_limit"
    PAGE_LIMIT = "page_limit"
    TIME_BUDGET = "time_budget"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    CANCELLED = "cancelled"


class EndpointSource(StrEnum):
    BASE = "base"
    LINK = "link"
    STYLESHEET = "stylesheet"
    SCRIPT = "script"
    IMAGE = "image"
    FRAME = "frame"
    FORM = "form"
    REDIRECT = "redirect"
    ROBOTS = "robots"
    SITEMAP = "sitemap"


class SkipReason(StrEnum):
    OUT_OF_SCOPE = "out_of_scope"
    QUERY_STRING = "query_string"
    RISKY_PATH = "risky_path"
    FORM_NOT_SUBMITTED = "form_not_submitted"
    STATIC_ASSET = "static_asset"
    DEPTH_LIMIT = "depth_limit"
    NOT_REACHED = "not_reached"  # still queued when the scan stopped


class EventLevel(StrEnum):
    INFO = "info"
    WARNING = "warning"
    BLOCKED = "blocked"


@dataclass
class CookieObservation:
    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    domain: str | None
    path: str | None
    has_expiry: bool


@dataclass
class TechHint:
    source: str  # e.g. "header:server", "meta:generator", "cookie:PHPSESSID"
    value: str


@dataclass
class Evidence:
    """One HTTP exchange, redacted."""

    id: str
    method: str
    url: str
    request_headers: list[tuple[str, str]]
    status: int
    response_headers: list[tuple[str, str]]
    body_excerpt: str
    body_sha256: str
    body_bytes_captured: int
    truncated: bool
    peer: str
    redactions: list[str]


@dataclass
class PageObservation:
    url: str
    method: str
    status: int
    depth: int
    content_type: str | None
    declared_length: int | None
    body_bytes: int
    truncated: bool
    elapsed_ms: int
    title: str | None
    redirect_location: str | None
    allowed_methods: list[str] | None
    cookies: list[CookieObservation]
    hints: list[TechHint]
    evidence_id: str


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str
    source: EndpointSource
    found_on: str | None
    fetched: bool
    skip_reason: SkipReason | None = None
    query_param_names: list[str] = field(default_factory=list)


@dataclass
class ScanEvent:
    at: datetime
    level: EventLevel
    code: str
    message: str
    url: str | None = None


@dataclass
class DiscoveryResult:
    target_id: uuid.UUID
    assessment_id: uuid.UUID
    authorization_id: uuid.UUID
    authorization_version: int
    started_at: datetime
    finished_at: datetime | None = None
    stop_reason: StopReason | None = None
    requests_sent: int = 0
    pages: list[PageObservation] = field(default_factory=list)
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    events: list[ScanEvent] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        converted = _jsonable(asdict(self))
        assert isinstance(converted, dict)  # noqa: S101  # asdict always returns a dict
        return converted


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID | StrEnum):
        return str(value)
    return value
