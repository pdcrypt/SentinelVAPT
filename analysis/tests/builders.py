"""Small builders for ScanObservations fixtures. Plain values only."""

import itertools
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from sentinel_analysis.observations import (
    CookieObs,
    EndpointObs,
    EventObs,
    ResponseObs,
    ScanInfo,
    ScanObservations,
)

_ids = itertools.count(1)


def new_id(prefix: str) -> str:
    return f"{prefix}-{next(_ids):04d}"


@dataclass
class Page:
    url: str
    method: str = "GET"
    status: int = 200
    headers: Sequence[tuple[str, str]] = ()
    body: str = ""
    title: str | None = None
    html: bool = True
    truncated: bool = False
    cookies: Sequence[CookieObs] = ()  # endpoint_id is filled in by build()
    endpoint_id: str = field(default_factory=lambda: new_id("endpoint"))
    evidence_id: str = field(default_factory=lambda: new_id("evidence"))

    def endpoint(self) -> EndpointObs:
        return EndpointObs(
            id=self.endpoint_id,
            asset_id=None,
            method=self.method,
            url=self.url,
            source="link",
            fetched=True,
            status=self.status,
            content_type="text/html" if self.html else "application/json",
            title=self.title,
        )

    def response(self) -> ResponseObs:
        headers = list(self.headers)
        if not any(name.lower() == "content-type" for name, _ in headers):
            headers.append(
                ("Content-Type", "text/html; charset=utf-8" if self.html else "application/json")
            )
        return ResponseObs(
            evidence_id=self.evidence_id,
            endpoint_id=self.endpoint_id,
            method=self.method,
            url=self.url,
            status=self.status,
            headers=tuple(headers),
            body_excerpt=self.body,
            truncated=self.truncated,
        )


def cookie(
    name: str, *, secure: bool = False, http_only: bool = False, same_site: str | None = None
) -> CookieObs:
    return CookieObs(
        endpoint_id="", name=name, secure=secure, http_only=http_only, same_site=same_site
    )


def build(
    pages: Iterable[Page] = (),
    *,
    events: Iterable[EventObs] = (),
    stop_reason: str | None = "completed",
    allow_untrusted_tls: bool = False,
) -> ScanObservations:
    pages = list(pages)
    cookies = [
        CookieObs(p.endpoint_id, c.name, c.secure, c.http_only, c.same_site)
        for p in pages
        for c in p.cookies
    ]
    return ScanObservations(
        scan=ScanInfo(
            scan_id="scan-1", stop_reason=stop_reason, allow_untrusted_tls=allow_untrusted_tls
        ),
        endpoints=tuple(p.endpoint() for p in pages),
        responses=tuple(p.response() for p in pages),
        cookies=tuple(cookies),
        events=tuple(events),
    )


def tls_event(url: str, reason: str = "CERTIFICATE_VERIFY_FAILED") -> EventObs:
    return EventObs(level="warning", code="tls_error", message=f"TLS error: {reason}", url=url)


SECURE_HEADERS: tuple[tuple[str, str], ...] = (
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
)
