"""SafeHttpClient: the only code in the scanner that opens network connections.

Every request, including every redirect hop, passes these steps in order:

1. method allowlist (GET, HEAD, OPTIONS; no request bodies exist in the API)
2. guard: authorization window still active, not cancelled, time budget left
3. request budget
4. ScopePolicy.check_url: scheme, exact host, port, canonical path, exclusions
5. DNS resolution, then ScopePolicy.check_address on *every* resolved address
6. rate limiter (then the guard again, since waiting takes time)
7. connect to the checked IP itself (no second resolution: no DNS rebinding),
   sending the original hostname as Host header and TLS SNI
8. bounded read: a byte cap, and a wall-clock deadline enforced by a watchdog
   that shuts the socket down, so slow or dripping responses cannot overrun it

Never: automatic redirects, proxies (environment variables are not read),
cookies, credentials, compression (Accept-Encoding: identity; bodies are never
decompressed).
"""

import contextlib
import http.client
import socket
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from urllib.parse import urljoin

from sentinel_scanner.errors import RequestFailed, RequestLimitReached, ScopeViolation
from sentinel_scanner.limits import ScanLimits
from sentinel_scanner.netaddr import IPAddress
from sentinel_scanner.ratelimit import RateLimiter
from sentinel_scanner.resolver import Resolver
from sentinel_scanner.scope import CheckedUrl, ScopePolicy
from sentinel_scanner.version import USER_AGENT


class HttpMethod(StrEnum):
    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


SAFE_METHODS = frozenset(HttpMethod)
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_READ_CHUNK = 64 * 1024

REQUEST_HEADERS: tuple[tuple[str, str], ...] = (
    ("User-Agent", USER_AGENT),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Encoding", "identity"),
    ("Connection", "close"),
)


@dataclass(frozen=True)
class HttpResponse:
    method: HttpMethod
    url: str  # the canonical URL that was requested
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    truncated: bool
    elapsed_s: float
    peer: str  # the IP address actually contacted

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        return next((v for k, v in self.headers if k.lower() == lowered), None)

    def header_values(self, name: str) -> list[str]:
        lowered = name.lower()
        return [v for k, v in self.headers if k.lower() == lowered]

    @property
    def location(self) -> str | None:
        if self.status in REDIRECT_STATUSES:
            return self.header("Location")
        return None


@dataclass(frozen=True)
class FetchResult:
    """A request and the redirects followed from it, in order."""

    responses: tuple[HttpResponse, ...]
    blocked_redirect: ScopeViolation | None = None
    redirect_failure: RequestFailed | None = None
    redirect_limit_reached: bool = False

    @property
    def final(self) -> HttpResponse:
        return self.responses[-1]


class Connector(Protocol):
    def open(
        self,
        *,
        scheme: str,
        ip: IPAddress,
        port: int,
        server_hostname: str,
        timeout: float,
        verify_tls: bool,
    ) -> http.client.HTTPConnection: ...


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a fixed IP, with the original hostname used for SNI and
    certificate verification."""

    def __init__(
        self, ip: str, port: int, timeout: float, context: ssl.SSLContext, server_hostname: str
    ) -> None:
        super().__init__(ip, port, timeout=timeout, context=context)
        self._sentinel_context = context
        self._sentinel_server_hostname = server_hostname

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._sentinel_context.wrap_socket(
            sock, server_hostname=self._sentinel_server_hostname
        )


class PinnedConnector:
    """Opens connections to an already-checked IP address; never resolves names."""

    def open(
        self,
        *,
        scheme: str,
        ip: IPAddress,
        port: int,
        server_hostname: str,
        timeout: float,
        verify_tls: bool,
    ) -> http.client.HTTPConnection:
        if scheme == "https":
            context = ssl.create_default_context()
            if not verify_tls:
                # Explicit opt-in for lab targets with self-signed certificates.
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            return _PinnedHTTPSConnection(str(ip), port, timeout, context, server_hostname)
        return http.client.HTTPConnection(str(ip), port, timeout=timeout)


class SafeHttpClient:
    def __init__(
        self,
        policy: ScopePolicy,
        limits: ScanLimits,
        *,
        guard: Callable[[], None],
        resolver: Resolver,
        connector: Connector,
        rate_limiter: RateLimiter,
        clock: Callable[[], float],
        verify_tls: bool = True,
    ) -> None:
        self.policy = policy
        self.limits = limits
        self.guard = guard
        self.resolver = resolver
        self.connector = connector
        self.rate_limiter = rate_limiter
        self.clock = clock
        self.verify_tls = verify_tls
        self._sent = 0

    @property
    def requests_sent(self) -> int:
        return self._sent

    def request(self, method: HttpMethod, url: str) -> HttpResponse:
        """Send one request (no redirect following) after every check passes."""
        if not isinstance(method, HttpMethod) or method not in SAFE_METHODS:
            raise ValueError(f"HTTP method {method!r} is not allowed")
        self.guard()
        if self._sent >= self.limits.max_requests:
            raise RequestLimitReached(f"request limit of {self.limits.max_requests} reached")

        checked = self.policy.check_url(url)
        addresses = self.resolver.resolve(checked.host, checked.port, self.limits.request_timeout_s)
        for ip in addresses:  # every address, not just the one we will use
            self.policy.check_address(ip, checked.host)

        self.rate_limiter.acquire()
        self.guard()
        self._sent += 1
        return self._send(method, checked, addresses[0])

    def fetch(self, method: HttpMethod, url: str) -> FetchResult:
        """Request `url` and follow redirects manually; each hop is a full,
        independently checked request. A first-hop ScopeViolation or
        RequestFailed propagates; later hops are reported in the result."""
        responses = [self.request(method, url)]
        current_method = method
        for _ in range(self.limits.max_redirects):
            location = responses[-1].location
            if not location:
                return FetchResult(tuple(responses))
            if responses[-1].status == 303 and current_method is not HttpMethod.HEAD:
                current_method = HttpMethod.GET
            next_url = urljoin(responses[-1].url, location)
            try:
                responses.append(self.request(current_method, next_url))
            except ScopeViolation as exc:
                return FetchResult(tuple(responses), blocked_redirect=exc)
            except RequestFailed as exc:
                return FetchResult(tuple(responses), redirect_failure=exc)
        return FetchResult(
            tuple(responses), redirect_limit_reached=responses[-1].location is not None
        )

    # --- wire ----------------------------------------------------------------------

    def _send(self, method: HttpMethod, checked: CheckedUrl, ip: IPAddress) -> HttpResponse:
        timeout = self.limits.request_timeout_s
        start = self.clock()
        conn = self.connector.open(
            scheme=checked.scheme,
            ip=ip,
            port=checked.port,
            server_hostname=checked.host,
            timeout=timeout,
            verify_tls=self.verify_tls,
        )
        timed_out = threading.Event()
        watchdog: threading.Timer | None = None
        try:
            conn.connect()  # bounded by the socket timeout
            sock = conn.sock
            remaining = timeout - (self.clock() - start)
            if remaining <= 0:
                raise TimeoutError
            watchdog = threading.Timer(remaining, _abort, args=(sock, timed_out))
            watchdog.daemon = True
            watchdog.start()

            conn.putrequest(method.value, checked.target, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", checked.netloc)
            for name, value in REQUEST_HEADERS:
                conn.putheader(name, value)
            conn.endheaders()
            response = conn.getresponse()
            body, truncated = self._read_body(response)
            if timed_out.is_set():
                raise TimeoutError
            return HttpResponse(
                method=method,
                url=checked.url,
                status=response.status,
                reason=response.reason,
                headers=tuple(response.getheaders()),
                body=body,
                truncated=truncated,
                elapsed_s=self.clock() - start,
                peer=str(ip),
            )
        except TimeoutError:
            raise RequestFailed("timeout", f"no complete response within {timeout}s") from None
        except ssl.SSLError as exc:
            raise RequestFailed("tls_error", f"TLS error: {exc.reason or exc}") from None
        except (OSError, http.client.HTTPException) as exc:
            if timed_out.is_set():
                raise RequestFailed("timeout", f"no complete response within {timeout}s") from None
            raise RequestFailed("connection_error", f"{type(exc).__name__}: {exc}") from None
        finally:
            if watchdog is not None:
                watchdog.cancel()
            conn.close()

    def _read_body(self, response: http.client.HTTPResponse) -> tuple[bytes, bool]:
        limit = self.limits.max_response_bytes
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(min(_READ_CHUNK, limit - total + 1))
            if not chunk:
                return b"".join(chunks), False
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                return b"".join(chunks)[:limit], True


def _abort(sock: socket.socket | None, flag: threading.Event) -> None:
    """Watchdog: end a request that overran its deadline by shutting the socket
    down, which unblocks any pending read immediately."""
    flag.set()
    if sock is None:
        return
    with contextlib.suppress(OSError):
        sock.shutdown(socket.SHUT_RDWR)
