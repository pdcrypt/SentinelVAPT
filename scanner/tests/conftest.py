"""Deterministic local fixtures. Nothing here touches a public network.

LabServer is a real HTTP server bound to 127.0.0.1 on an ephemeral port, with
scripted routes. The hostnames used in tests (lab.test, evil.test) resolve via
StaticResolver to 127.0.0.1, so "out of scope" requests *would* reach the same
server if the scanner let them through; the server's request log proves they
did not.
"""

import contextlib
import http.client
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from sentinel_scanner.grant import ScanGrant, ScopeSnapshot, validate_grant
from sentinel_scanner.limits import ScanLimits
from sentinel_scanner.netaddr import IPAddress
from sentinel_scanner.ratelimit import RateLimiter
from sentinel_scanner.resolver import StaticResolver
from sentinel_scanner.transport import PinnedConnector, SafeHttpClient

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


# --- Local HTTP server -------------------------------------------------------------


@dataclass
class Route:
    status: int = 200
    body: bytes = b""
    headers: list[tuple[str, str]] = field(default_factory=list)
    content_type: str = "text/html; charset=utf-8"
    delay_s: float = 0.0  # before sending anything
    drip_interval_s: float = 0.0  # send the body one byte at a time
    chunked: bool = False


@dataclass
class Received:
    method: str
    path: str
    headers: dict[str, str]

    @property
    def host(self) -> str:
        return self.headers.get("host", "")


class LabServer:
    def __init__(self) -> None:
        self.routes: dict[str, Route] = {}
        self.requests: list[Received] = []
        self._lock = threading.Lock()
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _handle(self) -> None:
                with server._lock:
                    server.requests.append(
                        Received(
                            self.command,
                            self.path,
                            {k.lower(): v for k, v in self.headers.items()},
                        )
                    )
                route = server.routes.get(self.path) or server.routes.get(
                    self.path.split("?", 1)[0]
                )
                if route is None:
                    route = Route(status=404, body=b"not found", content_type="text/plain")
                if route.delay_s:
                    time.sleep(route.delay_s)
                # The client may hang up early (timeouts, truncation): that is expected.
                with contextlib.suppress(
                    BrokenPipeError, ConnectionResetError, ConnectionAbortedError
                ):
                    self._respond(route)

            def _respond(self, route: Route) -> None:
                self.send_response(route.status)
                self.send_header("Content-Type", route.content_type)
                for name, value in route.headers:
                    self.send_header(name, value)
                send_body = self.command != "HEAD"
                if route.chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    if send_body:
                        for i in range(0, len(route.body), 4096):
                            piece = route.body[i : i + 4096]
                            self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
                        self.wfile.write(b"0\r\n\r\n")
                    return
                self.send_header("Content-Length", str(len(route.body)))
                self.end_headers()
                if not send_body:
                    return
                if route.drip_interval_s:
                    for byte in route.body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(route.drip_interval_s)
                else:
                    self.wfile.write(route.body)

            do_GET = do_HEAD = do_OPTIONS = do_POST = do_PUT = do_DELETE = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.httpd.block_on_close = False
        self.port = int(self.httpd.server_address[1])
        self._thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def route(self, path: str, **kwargs: Any) -> None:
        if "body" in kwargs and isinstance(kwargs["body"], str):
            kwargs["body"] = kwargs["body"].encode()
        self.routes[path] = Route(**kwargs)

    def html(self, path: str, body: str, **kwargs: Any) -> None:
        self.route(path, body=f"<!doctype html><html>{body}</html>", **kwargs)

    def redirect(self, path: str, location: str, status: int = 302) -> None:
        self.route(path, status=status, headers=[("Location", location)], content_type="text/plain")

    def url(self, path: str = "/", host: str = "lab.test") -> str:
        return f"http://{host}:{self.port}{path}"

    def paths(self, method: str = "GET") -> list[str]:
        return [r.path for r in self.requests if r.method == method]

    @property
    def hosts_seen(self) -> set[str]:
        return {r.host.split(":")[0] for r in self.requests}


@pytest.fixture
def lab() -> Iterator[LabServer]:
    server = LabServer()
    server.start()
    yield server
    server.stop()


# --- Time, resolution, connections ---------------------------------------------------


class FakeTime:
    """Wall clock (for the authorization window) and monotonic clock (for rate
    limiting and budgets). Sleeping advances both instantly."""

    def __init__(self, now: datetime = NOW) -> None:
        self.wall = now
        self.mono = 1000.0
        self.sleeps: list[float] = []

    def now(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.advance(seconds)

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.wall += timedelta(seconds=seconds)


@pytest.fixture
def fake_time() -> FakeTime:
    return FakeTime()


def lab_resolver(**extra: list[str]) -> StaticResolver:
    mapping: dict[str, list[str]] = {"lab.test": ["127.0.0.1"], "evil.test": ["127.0.0.1"]}
    mapping.update({k.replace("_", "."): v for k, v in extra.items()})
    return StaticResolver(mapping)


@dataclass
class Connection:
    scheme: str
    ip: str
    port: int
    server_hostname: str


class SpyConnector:
    """Records every connection the transport opens."""

    def __init__(self) -> None:
        self.inner = PinnedConnector()
        self.opened: list[Connection] = []

    def open(self, **kwargs: Any) -> http.client.HTTPConnection:
        ip: IPAddress = kwargs["ip"]
        self.opened.append(
            Connection(kwargs["scheme"], str(ip), kwargs["port"], kwargs["server_hostname"])
        )
        return self.inner.open(**kwargs)


@pytest.fixture
def spy() -> SpyConnector:
    return SpyConnector()


# --- Grants and clients --------------------------------------------------------------


def make_grant(lab: LabServer, **overrides: Any) -> ScanGrant:
    scope_overrides = overrides.pop("scope", {})
    scope: dict[str, Any] = {
        "base_url": lab.url("/"),
        "environment": "local_lab",
        "in_scope_hosts": ("lab.test",),
        "allowed_ports": (lab.port,),
        "in_scope_path_prefixes": ("/",),
        "excluded_paths": (),
    }
    scope.update(scope_overrides)
    values: dict[str, Any] = {
        "target_id": uuid.uuid4(),
        "assessment_id": uuid.uuid4(),
        "authorization_id": uuid.uuid4(),
        "authorization_version": 1,
        "assessment_status": "in_progress",
        "valid_from": NOW - timedelta(hours=1),
        "valid_until": NOW + timedelta(hours=1),
        "scope": ScopeSnapshot(**scope),
    }
    values.update(overrides)
    return ScanGrant(**values)


def make_client(
    lab: LabServer,
    *,
    limits: ScanLimits | None = None,
    time_source: FakeTime | None = None,
    connector: Any = None,
    resolver: Any = None,
    guard: Callable[[], None] | None = None,
    **scope: Any,
) -> SafeHttpClient:
    """A SafeHttpClient for one grant, using real time unless a FakeTime is given."""
    grant = make_grant(lab, scope=scope)
    policy = validate_grant(grant, NOW)
    limits = limits or ScanLimits(max_requests_per_second=20.0)
    clock = time_source.monotonic if time_source else time.monotonic
    sleep = time_source.sleep if time_source else time.sleep
    return SafeHttpClient(
        policy,
        limits,
        guard=guard or (lambda: None),
        resolver=resolver or lab_resolver(),
        connector=connector or PinnedConnector(),
        rate_limiter=RateLimiter(limits.min_request_interval_s, clock=clock, sleep=sleep),
        clock=clock,
    )
