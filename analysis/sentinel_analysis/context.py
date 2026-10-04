"""RuleContext: bounded, normalized, indexed view of one scan's observations.

Built once per analysis. Rules read from it instead of walking the raw
observation graph, so parsing of untrusted values happens in one place and
iteration order is deterministic by construction (everything is sorted).
"""

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace

from sentinel_analysis.observations import (
    AssetObs,
    CookieObs,
    EndpointObs,
    EventObs,
    ResponseObs,
    ScanInfo,
    ScanObservations,
)
from sentinel_analysis.parsing import (
    MAX_HEADER_VALUE,
    MAX_URL,
    is_html,
    origin_key,
    scheme_of,
)

# Bounds applied regardless of what the caller passes (defence in depth; the
# scanner's own caps are far lower).
MAX_ASSETS = 500
MAX_ENDPOINTS = 5000
MAX_RESPONSES = 1000
MAX_COOKIES = 5000
MAX_EVENTS = 5000
MAX_HEADERS_PER_RESPONSE = 200
MAX_HEADER_NAME = 128
MAX_EXCERPT = 8192
MAX_TEXT = 512


def _clip(value: str | None, limit: int) -> str | None:
    return None if value is None else value[:limit]


def _bound_response(r: ResponseObs) -> ResponseObs:
    headers = tuple(
        (name[:MAX_HEADER_NAME].strip().lower(), value[:MAX_HEADER_VALUE])
        for name, value in r.headers[:MAX_HEADERS_PER_RESPONSE]
    )
    return replace(
        r,
        url=r.url[:MAX_URL],
        method=r.method[:16].upper(),
        headers=headers,
        body_excerpt=r.body_excerpt[:MAX_EXCERPT],
    )


@dataclass(frozen=True)
class CookieSite:
    """A cookie, the endpoint whose response set it, and that endpoint's origin."""

    cookie: CookieObs
    endpoint: EndpointObs
    origin: str
    scheme: str


class RuleContext:
    def __init__(self, observations: ScanObservations) -> None:
        self.scan: ScanInfo = observations.scan
        # Inputs over a limit are cut AFTER sorting, so what is kept does not
        # depend on input order; `truncated` lets the engine report it.
        self.truncated = (
            len(observations.assets) > MAX_ASSETS
            or len(observations.endpoints) > MAX_ENDPOINTS
            or len(observations.responses) > MAX_RESPONSES
            or len(observations.cookies) > MAX_COOKIES
            or len(observations.events) > MAX_EVENTS
        )
        self.assets: tuple[AssetObs, ...] = tuple(
            sorted(observations.assets, key=lambda a: (a.scheme, a.host, a.port, a.id))[:MAX_ASSETS]
        )
        self.endpoints: tuple[EndpointObs, ...] = tuple(
            sorted(
                (
                    replace(e, url=e.url[:MAX_URL], title=_clip(e.title, MAX_TEXT))
                    for e in observations.endpoints
                ),
                key=lambda e: (e.url, e.method, e.id),
            )[:MAX_ENDPOINTS]
        )
        self.responses: tuple[ResponseObs, ...] = tuple(
            sorted(
                (_bound_response(r) for r in observations.responses),
                key=lambda r: (r.url, r.method, r.evidence_id),
            )[:MAX_RESPONSES]
        )
        self.events: tuple[EventObs, ...] = tuple(
            sorted(
                (
                    replace(e, message=e.message[:MAX_TEXT], url=_clip(e.url, MAX_URL))
                    for e in observations.events
                ),
                key=lambda e: (e.code, e.url or "", e.message, e.level),
            )[:MAX_EVENTS]
        )

        self._endpoints_by_id = {e.id: e for e in self.endpoints}
        self.evidence_ids = frozenset(r.evidence_id for r in self.responses)

        by_origin: dict[str, list[ResponseObs]] = defaultdict(list)
        by_endpoint: dict[str, list[ResponseObs]] = defaultdict(list)
        for response in self.responses:
            origin = origin_key(response.url)
            if origin is not None:
                by_origin[origin].append(response)
            if response.endpoint_id is not None:
                by_endpoint[response.endpoint_id].append(response)
        self._responses_by_origin = {k: tuple(v) for k, v in by_origin.items()}
        self._responses_by_endpoint = {k: tuple(v) for k, v in by_endpoint.items()}
        self.origins: tuple[str, ...] = tuple(sorted(self._responses_by_origin))

        sites = []
        ordered_cookies = sorted(
            observations.cookies,
            key=lambda c: (c.endpoint_id, c.name, c.secure, c.http_only, c.same_site or ""),
        )[:MAX_COOKIES]
        for cookie in ordered_cookies:
            endpoint = self._endpoints_by_id.get(cookie.endpoint_id)
            if endpoint is None:
                continue
            origin = origin_key(endpoint.url)
            if origin is None:
                continue
            sites.append(
                CookieSite(
                    replace(cookie, name=cookie.name[:200]),
                    endpoint,
                    origin,
                    scheme_of(endpoint.url),
                )
            )
        self.cookie_sites: tuple[CookieSite, ...] = tuple(
            sorted(
                sites, key=lambda s: (s.origin, s.cookie.name, s.endpoint.url, s.endpoint.method)
            )
        )

    # --- lookups ------------------------------------------------------------------

    def responses_at(self, origin: str) -> tuple[ResponseObs, ...]:
        return self._responses_by_origin.get(origin, ())

    def responses_for_endpoint(self, endpoint_id: str) -> tuple[ResponseObs, ...]:
        return self._responses_by_endpoint.get(endpoint_id, ())

    def endpoint(self, endpoint_id: str | None) -> EndpointObs | None:
        return self._endpoints_by_id.get(endpoint_id) if endpoint_id else None

    def events_with_code(self, code: str) -> tuple[EventObs, ...]:
        return tuple(e for e in self.events if e.code == code)

    # --- helpers --------------------------------------------------------------------

    @staticmethod
    def header(response: ResponseObs, name: str) -> str | None:
        lowered = name.lower()
        return next((v for k, v in response.headers if k == lowered), None)

    @staticmethod
    def header_values(response: ResponseObs, name: str) -> tuple[str, ...]:
        lowered = name.lower()
        return tuple(v for k, v in response.headers if k == lowered)

    def is_html(self, response: ResponseObs) -> bool:
        return is_html(self.header(response, "content-type"))

    @staticmethod
    def is_success(response: ResponseObs) -> bool:
        return 200 <= response.status < 300

    @staticmethod
    def evidence_of(responses: Iterable[ResponseObs]) -> tuple[str, ...]:
        return tuple(sorted({r.evidence_id for r in responses}))
