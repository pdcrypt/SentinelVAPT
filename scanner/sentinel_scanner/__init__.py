"""SentinelVAPT scanner engine.

A standalone package: it receives a scan grant (assessment + authorization +
scope snapshot) and returns structured, redacted discovery results. It must not
import from the backend, touch the database, or read secrets from the
environment. All network access goes through sentinel_scanner.transport.

Public API: run_discovery(), ScanGrant, ScopeSnapshot, DiscoveryConfig,
ScanLimits, CrawlOptions, CancellationToken, DiscoveryResult, GrantRejected.
"""

from sentinel_scanner.api import CancellationToken, DiscoveryConfig, run_discovery
from sentinel_scanner.discovery.crawler import CrawlOptions
from sentinel_scanner.errors import GrantRejected
from sentinel_scanner.grant import ScanGrant, ScopeSnapshot
from sentinel_scanner.limits import ScanLimits
from sentinel_scanner.models import DiscoveryResult, StopReason
from sentinel_scanner.version import __version__

__all__ = [
    "CancellationToken",
    "CrawlOptions",
    "DiscoveryConfig",
    "DiscoveryResult",
    "GrantRejected",
    "ScanGrant",
    "ScanLimits",
    "ScopeSnapshot",
    "StopReason",
    "__version__",
    "run_discovery",
]
