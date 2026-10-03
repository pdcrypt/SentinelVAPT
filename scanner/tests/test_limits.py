"""Request count, response size and timeout limits, and the hard caps."""

import socket
import time
from dataclasses import fields

import pytest

from sentinel_scanner.errors import RequestFailed, RequestLimitReached
from sentinel_scanner.limits import HARD_CAPS, ScanLimits
from sentinel_scanner.transport import HttpMethod
from tests.conftest import LabServer, make_client


def limits(**overrides: float) -> ScanLimits:
    return ScanLimits(**{"max_requests_per_second": 20.0, **overrides})  # type: ignore[arg-type]


# --- Request count ---------------------------------------------------------------------


def test_request_limit_is_enforced(lab: LabServer) -> None:
    lab.html("/", "")
    client = make_client(lab, limits=limits(max_requests=2))
    client.request(HttpMethod.GET, lab.url("/"))
    client.request(HttpMethod.HEAD, lab.url("/"))
    with pytest.raises(RequestLimitReached):
        client.request(HttpMethod.GET, lab.url("/"))
    assert len(lab.requests) == 2


def test_redirect_hops_count_towards_the_limit(lab: LabServer) -> None:
    lab.redirect("/a", "/b")
    lab.redirect("/b", "/c")
    lab.html("/c", "")
    client = make_client(lab, limits=limits(max_requests=2))
    with pytest.raises(RequestLimitReached):
        client.fetch(HttpMethod.GET, lab.url("/a"))
    assert lab.paths() == ["/a", "/b"]


def test_blocked_requests_do_not_use_the_budget(lab: LabServer) -> None:
    client = make_client(lab, limits=limits(max_requests=1))
    for _ in range(5):
        with pytest.raises(Exception):  # noqa: B017  # ScopeViolation
            client.request(HttpMethod.GET, "http://evil.test/")
    assert client.requests_sent == 0


# --- Response size ---------------------------------------------------------------------


@pytest.mark.parametrize("chunked", [False, True])
def test_response_size_is_capped(lab: LabServer, chunked: bool) -> None:
    lab.route("/big", body=b"x" * 200_000, chunked=chunked, content_type="text/plain")
    client = make_client(lab, limits=limits(max_response_bytes=1024))
    response = client.request(HttpMethod.GET, lab.url("/big"))
    assert response.truncated
    assert len(response.body) == 1024


def test_body_exactly_at_the_limit_is_not_truncated(lab: LabServer) -> None:
    lab.route("/exact", body=b"y" * 1024, content_type="text/plain")
    response = make_client(lab, limits=limits(max_response_bytes=1024)).request(
        HttpMethod.GET, lab.url("/exact")
    )
    assert not response.truncated
    assert len(response.body) == 1024


# --- Timeouts --------------------------------------------------------------------------


def test_slow_server_times_out(lab: LabServer) -> None:
    lab.route("/slow", body=b"late", delay_s=3.0)
    client = make_client(lab, limits=limits(request_timeout_s=0.5))
    started = time.monotonic()
    with pytest.raises(RequestFailed) as exc:
        client.request(HttpMethod.GET, lab.url("/slow"))
    assert exc.value.code == "timeout"
    assert time.monotonic() - started < 2.0


def test_dripping_body_cannot_extend_the_deadline(lab: LabServer) -> None:
    """Each byte arrives well within a per-read timeout, but the whole response
    takes far longer than the deadline: the watchdog must end it."""
    lab.route("/drip", body=b"z" * 100, drip_interval_s=0.1, content_type="text/plain")
    client = make_client(lab, limits=limits(request_timeout_s=0.6))
    started = time.monotonic()
    with pytest.raises(RequestFailed) as exc:
        client.request(HttpMethod.GET, lab.url("/drip"))
    assert exc.value.code == "timeout"
    assert time.monotonic() - started < 2.0


def test_connection_refused_is_a_request_failure(lab: LabServer) -> None:
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()  # nothing listens here now
    client = make_client(
        lab,
        allowed_ports=(lab.port, port),
    )
    with pytest.raises(RequestFailed) as exc:
        client.request(HttpMethod.GET, f"http://lab.test:{port}/")
    assert exc.value.code in {"connection_error", "timeout"}


# --- Hard caps -------------------------------------------------------------------------


@pytest.mark.parametrize("name", [f.name for f in fields(ScanLimits)])
def test_limits_cannot_exceed_hard_caps(name: str) -> None:
    cap = getattr(HARD_CAPS, name)
    with pytest.raises(ValueError, match=r"at most|between"):
        ScanLimits(**{name: cap * 2 if isinstance(cap, int) else cap * 2.0})
    ScanLimits(**{name: cap})  # the cap itself is allowed


@pytest.mark.parametrize("name", [f.name for f in fields(ScanLimits) if f.name != "max_redirects"])
def test_limits_must_be_positive(name: str) -> None:
    for bad in (0, -1):
        with pytest.raises(ValueError):
            ScanLimits(**{name: bad})


def test_defaults_are_conservative() -> None:
    defaults = ScanLimits()
    assert defaults.max_requests == 100
    assert defaults.max_requests_per_second == 5.0
    assert defaults.request_timeout_s == 10.0
    assert defaults.max_response_bytes == 1024 * 1024
