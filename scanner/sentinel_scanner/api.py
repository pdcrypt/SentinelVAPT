"""Public entry point: run_discovery().

The backend (Phase 3) builds a ScanGrant from the database and calls this.
Nothing here imports backend, web framework or database code.
"""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sentinel_scanner.discovery.crawler import Crawler, CrawlOptions
from sentinel_scanner.errors import (
    AuthorizationExpired,
    ScanCancelled,
    ScanStopped,
    TimeBudgetExhausted,
)
from sentinel_scanner.grant import ScanGrant, validate_grant
from sentinel_scanner.limits import ScanLimits
from sentinel_scanner.models import DiscoveryResult, EventLevel, ScanEvent, StopReason
from sentinel_scanner.ratelimit import RateLimiter
from sentinel_scanner.resolver import Resolver, SystemResolver
from sentinel_scanner.transport import Connector, PinnedConnector, SafeHttpClient


@dataclass(frozen=True)
class DiscoveryConfig:
    limits: ScanLimits = field(default_factory=ScanLimits)
    crawl: CrawlOptions = field(default_factory=CrawlOptions)
    # Lab targets often use self-signed certificates; turning verification off
    # must be an explicit choice.
    verify_tls: bool = True


class CancellationToken:
    """Thread-safe flag the caller can set to stop a running scan."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def run_discovery(
    grant: ScanGrant,
    config: DiscoveryConfig | None = None,
    *,
    cancel: CancellationToken | None = None,
    on_event: Callable[[ScanEvent], None] | None = None,
    resolver: Resolver | None = None,
    connector: Connector | None = None,
    now: Callable[[], datetime] = _utc_now,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> DiscoveryResult:
    """Run a passive discovery scan under `grant`.

    Raises GrantRejected, before any network I/O, if the grant does not
    permit scanning. Otherwise returns a DiscoveryResult; the scan stops early
    (see stop_reason) on limits, cancellation or authorization expiry.
    """
    config = config or DiscoveryConfig()
    limits = config.limits
    started_at = now()
    policy = validate_grant(grant, started_at)

    result = DiscoveryResult(
        target_id=grant.target_id,
        assessment_id=grant.assessment_id,
        authorization_id=grant.authorization_id,
        authorization_version=grant.authorization_version,
        started_at=started_at,
    )

    def emit(level: EventLevel, code: str, message: str, url: str | None) -> None:
        event = ScanEvent(at=now(), level=level, code=code, message=message, url=url)
        result.events.append(event)
        if on_event is not None:
            on_event(event)

    scan_deadline = monotonic() + limits.max_scan_seconds

    def guard() -> None:
        # Checked before every request (and again after rate-limit waits).
        if cancel is not None and cancel.cancelled:
            raise ScanCancelled("scan cancelled")
        if not grant.is_active_at(now()):
            raise AuthorizationExpired("authorization window has ended")
        if monotonic() >= scan_deadline:
            raise TimeBudgetExhausted(f"scan time budget of {limits.max_scan_seconds}s used")

    client = SafeHttpClient(
        policy,
        limits,
        guard=guard,
        resolver=resolver or SystemResolver(),
        connector=connector or PinnedConnector(),
        rate_limiter=RateLimiter(limits.min_request_interval_s, clock=monotonic, sleep=sleep),
        clock=monotonic,
        verify_tls=config.verify_tls,
    )
    crawler = Crawler(client, policy, limits, config.crawl, result, emit)

    emit(EventLevel.INFO, "scan_started", "discovery scan started", None)
    try:
        crawler.run(grant.scope.base_url)
        result.stop_reason = crawler.stop_reason or StopReason.COMPLETED
    except ScanStopped as exc:
        result.stop_reason = StopReason(exc.reason)
        emit(EventLevel.WARNING, exc.reason, exc.message, None)
    result.requests_sent = client.requests_sent
    result.finished_at = now()
    emit(EventLevel.INFO, "scan_finished", f"discovery scan finished: {result.stop_reason}", None)
    return result
