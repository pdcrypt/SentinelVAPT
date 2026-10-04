"""Input contract: what the backend hands to the rule engine.

Plain immutable values built from persisted Phase 3 rows (already redacted by
the scanner). No ORM objects, no database handles, no network. Identifiers are
strings so this package needs nothing from the backend.
"""

from dataclasses import dataclass

REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class ScanInfo:
    scan_id: str
    stop_reason: str | None
    allow_untrusted_tls: bool


@dataclass(frozen=True)
class AssetObs:
    id: str
    scheme: str
    host: str
    port: int


@dataclass(frozen=True)
class EndpointObs:
    id: str
    asset_id: str | None
    method: str
    url: str
    source: str
    fetched: bool
    status: int | None
    content_type: str | None
    title: str | None


@dataclass(frozen=True)
class ResponseObs:
    """One stored evidence record (a redacted HTTP exchange)."""

    evidence_id: str
    endpoint_id: str | None
    method: str
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body_excerpt: str
    truncated: bool


@dataclass(frozen=True)
class CookieObs:
    endpoint_id: str
    name: str
    secure: bool
    http_only: bool
    same_site: str | None


@dataclass(frozen=True)
class EventObs:
    level: str
    code: str
    message: str
    url: str | None


@dataclass(frozen=True)
class ScanObservations:
    scan: ScanInfo
    assets: tuple[AssetObs, ...] = ()
    endpoints: tuple[EndpointObs, ...] = ()
    responses: tuple[ResponseObs, ...] = ()
    cookies: tuple[CookieObs, ...] = ()
    events: tuple[EventObs, ...] = ()
