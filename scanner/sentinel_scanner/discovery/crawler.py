"""Breadth-first, passive crawl of in-scope pages.

Every request goes through SafeHttpClient; the crawler only decides *which*
in-scope URLs are worth requesting. Conservative by default: links with query
strings, risky-looking paths, forms and static assets are recorded but not
requested.
"""

import hashlib
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from sentinel_scanner.discovery.cookies import parse_set_cookie
from sentinel_scanner.discovery.hints import collect_hints
from sentinel_scanner.discovery.links import (
    ExtractedLink,
    HtmlDocument,
    extract_html,
    extract_robots,
    extract_sitemap,
)
from sentinel_scanner.errors import RequestFailed, ScopeViolation
from sentinel_scanner.limits import ScanLimits
from sentinel_scanner.models import (
    DiscoveredEndpoint,
    DiscoveryResult,
    EndpointSource,
    EventLevel,
    Evidence,
    PageObservation,
    SkipReason,
    StopReason,
)
from sentinel_scanner.redaction import redact_headers, redact_text, redact_url
from sentinel_scanner.scope import ScopePolicy
from sentinel_scanner.transport import REQUEST_HEADERS, HttpMethod, HttpResponse, SafeHttpClient

# Path words suggesting a GET may change state. Matched against path segments.
RISKY_PATH_WORDS = (
    "logout",
    "log-out",
    "signout",
    "sign-out",
    "logoff",
    "delete",
    "remove",
    "destroy",
    "reset",
    "unsubscribe",
    "purge",
    "revoke",
    "deactivate",
    "disable",
    "shutdown",
)
_NOT_FOLLOWED = {
    EndpointSource.FORM: SkipReason.FORM_NOT_SUBMITTED,
    EndpointSource.SCRIPT: SkipReason.STATIC_ASSET,
    EndpointSource.IMAGE: SkipReason.STATIC_ASSET,
    EndpointSource.STYLESHEET: SkipReason.STATIC_ASSET,
}

EmitEvent = Callable[[EventLevel, str, str, str | None], None]


@dataclass(frozen=True)
class CrawlOptions:
    follow_query_links: bool = False
    fetch_robots: bool = True
    fetch_sitemap: bool = True


def is_risky_path(path: str) -> bool:
    segments = [s.split(";", 1)[0] for s in path.lower().split("/") if s]
    return any(word in segment for segment in segments for word in RISKY_PATH_WORDS)


def _is_html(response: HttpResponse) -> bool:
    content_type = (response.header("Content-Type") or "").lower()
    return "text/html" in content_type or "application/xhtml+xml" in content_type


@dataclass
class _Queued:
    url: str
    depth: int
    source: EndpointSource


class Crawler:
    def __init__(
        self,
        client: SafeHttpClient,
        policy: ScopePolicy,
        limits: ScanLimits,
        options: CrawlOptions,
        result: DiscoveryResult,
        emit: EmitEvent,
    ) -> None:
        self.client = client
        self.policy = policy
        self.limits = limits
        self.options = options
        self.result = result
        self.emit = emit
        self.stop_reason: StopReason | None = None
        self._queue: deque[_Queued] = deque()
        self._seen: set[str] = set()
        self._endpoints: dict[tuple[str, str], DiscoveredEndpoint] = {}
        self._endpoint_cap_reported = False

    # --- public ----------------------------------------------------------------

    def run(self, base_url: str) -> None:
        base = self.policy.check_url(base_url)  # validated by the grant already
        self._enqueue(base.url, 0, EndpointSource.BASE, None)
        self._probe_options(base.url)
        origin = f"{base.scheme}://{base.netloc}"
        if self.options.fetch_robots:
            self._consider(
                ExtractedLink(f"{origin}/robots.txt", EndpointSource.ROBOTS), None, 1, quiet=True
            )
        if self.options.fetch_sitemap:
            self._consider(
                ExtractedLink(f"{origin}/sitemap.xml", EndpointSource.SITEMAP), None, 1, quiet=True
            )
        try:
            while self._queue:
                if len(self.result.pages) >= self.limits.max_pages:
                    self.stop_reason = StopReason.PAGE_LIMIT
                    self.emit(EventLevel.INFO, "page_limit", "page limit reached", None)
                    return
                self._visit(self._queue.popleft())
        finally:
            self._mark_unreached()

    # --- requests ----------------------------------------------------------------

    def _probe_options(self, url: str) -> None:
        try:
            response = self.client.request(HttpMethod.OPTIONS, url)
        except (ScopeViolation, RequestFailed) as exc:
            self._report_failure(exc, url)
            return
        self._record_page(response, 0, None)

    def _visit(self, item: _Queued) -> None:
        try:
            fetched = self.client.fetch(HttpMethod.GET, item.url)
        except (ScopeViolation, RequestFailed) as exc:
            self._report_failure(exc, item.url)
            return
        self._endpoint(item.url, "GET").fetched = True

        document: HtmlDocument | None = None
        for hop, response in enumerate(fetched.responses):
            if hop:
                self._seen.add(response.url)
                endpoint = self._endpoint(response.url, "GET", EndpointSource.REDIRECT)
                endpoint.fetched = True
            document = self._record_page(response, item.depth, None)

        if fetched.blocked_redirect is not None:
            blocked = fetched.blocked_redirect
            target = blocked.url or ""
            endpoint = self._endpoint(target, "GET", EndpointSource.REDIRECT, fetched.final.url)
            endpoint.skip_reason = SkipReason.OUT_OF_SCOPE
            self._report_failure(blocked, target)
        if fetched.redirect_failure is not None:
            self._report_failure(fetched.redirect_failure, fetched.final.url)
        if fetched.redirect_limit_reached:
            self.emit(
                EventLevel.WARNING, "redirect_limit", "redirect limit reached", fetched.final.url
            )

        final = fetched.final
        next_depth = item.depth + 1
        text = final.body.decode("utf-8", "replace")
        if document is not None:
            for link in document.links:
                self._consider(link, final.url, next_depth)
        elif item.source is EndpointSource.ROBOTS and final.status == 200:
            for link in extract_robots(text, final.url):
                self._consider(link, final.url, next_depth)
        elif item.source is EndpointSource.SITEMAP and final.status == 200:
            for link in extract_sitemap(text, final.url):
                self._consider(link, final.url, next_depth)

    def _report_failure(self, exc: ScopeViolation | RequestFailed, url: str) -> None:
        level = EventLevel.BLOCKED if isinstance(exc, ScopeViolation) else EventLevel.WARNING
        self.emit(level, exc.code, exc.message, redact_url(url)[0] if url else None)

    # --- link decisions ----------------------------------------------------------

    def _consider(
        self, link: ExtractedLink, found_on: str | None, depth: int, *, quiet: bool = False
    ) -> None:
        try:
            checked = self.policy.check_url(link.url)
        except ScopeViolation:
            if not quiet:
                endpoint = self._endpoint(link.url, link.method, link.source, found_on)
                endpoint.skip_reason = SkipReason.OUT_OF_SCOPE
            return

        skip = _NOT_FOLLOWED.get(link.source)
        if skip is None and checked.query and not self.options.follow_query_links:
            skip = SkipReason.QUERY_STRING
        if skip is None and is_risky_path(checked.path):
            skip = SkipReason.RISKY_PATH
        if skip is None and depth > self.limits.max_depth:
            skip = SkipReason.DEPTH_LIMIT

        endpoint = self._endpoint(checked.url, link.method, link.source, found_on)
        if skip is not None:
            if not endpoint.fetched:
                endpoint.skip_reason = skip
            return
        self._enqueue(checked.url, depth, link.source, found_on)

    def _enqueue(self, url: str, depth: int, source: EndpointSource, found_on: str | None) -> None:
        if url in self._seen:
            return
        self._seen.add(url)
        self._endpoint(url, "GET", source, found_on)
        self._queue.append(_Queued(url, depth, source))

    def _mark_unreached(self) -> None:
        for item in self._queue:
            endpoint = self._endpoint(item.url, "GET")
            if not endpoint.fetched and endpoint.skip_reason is None:
                endpoint.skip_reason = SkipReason.NOT_REACHED

    # --- recording ---------------------------------------------------------------

    def _endpoint(
        self,
        url: str,
        method: str,
        source: EndpointSource = EndpointSource.LINK,
        found_on: str | None = None,
    ) -> DiscoveredEndpoint:
        key = (url, method)
        existing = self._endpoints.get(key)
        if existing is not None:
            return existing
        safe_url, _ = redact_url(url)
        query_names = sorted({k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})
        endpoint = DiscoveredEndpoint(
            url=safe_url,
            method=method,
            source=source,
            found_on=redact_url(found_on)[0] if found_on else None,
            fetched=False,
            query_param_names=query_names,
        )
        if len(self._endpoints) < self.limits.max_endpoints:
            self._endpoints[key] = endpoint
            self.result.endpoints.append(endpoint)
        elif not self._endpoint_cap_reported:
            self._endpoint_cap_reported = True
            self.emit(EventLevel.WARNING, "endpoint_limit", "endpoint limit reached", None)
        return endpoint

    def _record_page(
        self, response: HttpResponse, depth: int, _found_on: str | None
    ) -> HtmlDocument | None:
        document = None
        if _is_html(response) and response.method is HttpMethod.GET:
            document = extract_html(response.body.decode("utf-8", "replace"), response.url)

        cookies = [
            c for c in map(parse_set_cookie, response.header_values("Set-Cookie")) if c is not None
        ]
        evidence = self._evidence(response)
        allow = response.header("Allow") if response.method is HttpMethod.OPTIONS else None
        declared = response.header("Content-Length")
        location = response.location
        self.result.pages.append(
            PageObservation(
                url=redact_url(response.url)[0],
                method=response.method.value,
                status=response.status,
                depth=depth,
                content_type=response.header("Content-Type"),
                declared_length=int(declared) if declared and declared.isdigit() else None,
                body_bytes=len(response.body),
                truncated=response.truncated,
                elapsed_ms=round(response.elapsed_s * 1000),
                title=document.title if document else None,
                redirect_location=redact_url(location)[0] if location else None,
                allowed_methods=(
                    sorted({m.strip().upper() for m in allow.split(",") if m.strip()})
                    if allow
                    else None
                ),
                cookies=cookies,
                hints=collect_hints(
                    response.headers, cookies, document.generator if document else None
                ),
                evidence_id=evidence.id,
            )
        )
        return document

    def _evidence(self, response: HttpResponse) -> Evidence:
        parts = urlsplit(response.url)
        host = urlunsplit(("", parts.netloc, "", "", "")).lstrip("/")
        request_headers, request_redacted = redact_headers([("Host", host), *REQUEST_HEADERS])
        response_headers, response_redacted = redact_headers(response.headers)
        excerpt = response.body[: self.limits.body_excerpt_bytes].decode("utf-8", "replace")
        excerpt, body_kinds = redact_text(excerpt)
        url, url_changed = redact_url(response.url)
        redactions = [f"request_header:{n}" for n in request_redacted]
        redactions += [f"response_header:{n}" for n in response_redacted]
        redactions += [f"body:{k}" for k in body_kinds]
        if url_changed:
            redactions.append("url:query")
        evidence = Evidence(
            id=str(uuid.uuid4()),
            method=response.method.value,
            url=url,
            request_headers=request_headers,
            status=response.status,
            response_headers=response_headers,
            body_excerpt=excerpt,
            body_sha256=hashlib.sha256(response.body).hexdigest(),
            body_bytes_captured=len(response.body),
            truncated=response.truncated,
            peer=response.peer,
            redactions=redactions,
        )
        self.result.evidence.append(evidence)
        return evidence
