"""Scan limits: safe defaults, and hard caps that configuration cannot raise."""

from dataclasses import dataclass, fields

KIB = 1024
MIB = 1024 * KIB


@dataclass(frozen=True)
class HardCaps:
    max_requests: int = 500
    request_timeout_s: float = 30.0
    max_response_bytes: int = 5 * MIB
    max_requests_per_second: float = 20.0
    max_redirects: int = 5
    max_depth: int = 5
    max_pages: int = 200
    max_endpoints: int = 2000
    max_scan_seconds: float = 900.0
    body_excerpt_bytes: int = 8 * KIB


HARD_CAPS = HardCaps()


@dataclass(frozen=True)
class ScanLimits:
    max_requests: int = 100
    request_timeout_s: float = 10.0
    max_response_bytes: int = 1 * MIB
    max_requests_per_second: float = 5.0
    max_redirects: int = 5
    max_depth: int = 3
    max_pages: int = 50
    max_endpoints: int = 500
    max_scan_seconds: float = 300.0
    body_excerpt_bytes: int = 2 * KIB

    def __post_init__(self) -> None:
        for f in fields(self):
            value = getattr(self, f.name)
            cap = getattr(HARD_CAPS, f.name)
            if f.name == "max_redirects":
                if not 0 <= value <= cap:
                    raise ValueError(f"{f.name} must be between 0 and {cap}")
            elif not 0 < value <= cap:
                raise ValueError(f"{f.name} must be greater than 0 and at most {cap}")

    @property
    def min_request_interval_s(self) -> float:
        return 1.0 / self.max_requests_per_second
