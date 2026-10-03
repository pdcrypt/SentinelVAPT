from datetime import timedelta

import pytest
from tests.conftest import NOW, FakeTime, LabServer, make_client

from sentinel_scanner.errors import AuthorizationExpired
from sentinel_scanner.limits import ScanLimits
from sentinel_scanner.ratelimit import RateLimiter
from sentinel_scanner.transport import HttpMethod


def test_first_request_does_not_wait(fake_time: FakeTime) -> None:
    limiter = RateLimiter(0.5, clock=fake_time.monotonic, sleep=fake_time.sleep)
    assert limiter.acquire() == 0.0
    assert fake_time.sleeps == []


def test_requests_are_spaced(fake_time: FakeTime) -> None:
    limiter = RateLimiter(0.5, clock=fake_time.monotonic, sleep=fake_time.sleep)
    for _ in range(4):
        limiter.acquire()
    assert fake_time.sleeps == [0.5, 0.5, 0.5]


def test_idle_time_counts_towards_the_interval(fake_time: FakeTime) -> None:
    limiter = RateLimiter(0.5, clock=fake_time.monotonic, sleep=fake_time.sleep)
    limiter.acquire()
    fake_time.advance(0.3)
    limiter.acquire()
    fake_time.advance(1.0)
    limiter.acquire()
    assert fake_time.sleeps == pytest.approx([0.2])


def test_client_rate_limits_real_requests(lab: LabServer, fake_time: FakeTime) -> None:
    lab.html("/", "")
    client = make_client(lab, limits=ScanLimits(max_requests_per_second=4), time_source=fake_time)
    for _ in range(3):
        client.request(HttpMethod.GET, lab.url("/"))
    assert fake_time.sleeps == pytest.approx([0.25, 0.25])
    assert len(lab.requests) == 3


def test_guard_is_rechecked_after_waiting(lab: LabServer, fake_time: FakeTime) -> None:
    """If the authorization ends while waiting for a rate-limit slot, the
    request must not be sent."""
    lab.html("/", "")
    valid_until = NOW + timedelta(seconds=0.5)

    def guard() -> None:
        if fake_time.now() >= valid_until:
            raise AuthorizationExpired("expired")

    client = make_client(
        lab, limits=ScanLimits(max_requests_per_second=1), time_source=fake_time, guard=guard
    )
    client.request(HttpMethod.GET, lab.url("/"))
    with pytest.raises(AuthorizationExpired):
        client.request(HttpMethod.GET, lab.url("/"))  # waits 1s, crossing valid_until
    assert len(lab.requests) == 1
    assert client.requests_sent == 1
