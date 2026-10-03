"""Backend (configuration-time) and scanner (request-time) scope rules must
agree. They are separate implementations (ADR 0007); this shared corpus is the
guard against drift.

Allowed difference: the scanner may be *stricter* than the backend (it is the
enforcement point). It must never accept a host the backend rejects. Every
known stricter case is listed explicitly below, so a new divergence fails.
"""

import pytest

from app.core.errors import DomainValidationError
from app.models.enums import TargetEnvironment
from app.services.scope import validate_host
from sentinel_scanner.errors import ScopeViolation
from sentinel_scanner.scope import normalize_host

CORPUS = [
    # lab-style names
    "localhost",
    "LOCALHOST",
    "juice-shop",
    "server1",
    "web01",
    "api2.internal",
    "app.test",
    "dvwa.local",
    "node3.lan",
    "x1.home.arpa",
    "foo.localhost",
    "lab.test.",
    "cafe",
    "deadbeef",
    # public names
    "example.com",
    "staging.example.com",
    "0x1.example.com",
    "1password.com",
    "123.example.org",
    # IP literals
    "127.0.0.1",
    "10.0.0.5",
    "172.16.3.4",
    "192.168.1.20",
    "8.8.8.8",
    "100.64.0.1",
    "::1",
    "[::1]",
    "fd00::5",
    "2606:4700::1111",
    "::ffff:10.0.0.1",
    "::ffff:8.8.8.8",
    # always forbidden
    "169.254.169.254",
    "fe80::1",
    "0.0.0.0",  # noqa: S104  # an input that must be rejected, not a bind
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::ffff:169.254.169.254",
    "64:ff9b::a9fe:a9fe",
    # numeric spellings
    "0xa9fea9fe",
    "2852039166",
    "0251.0376.0251.0376",
    "0xa9.0xfe.0xa9.0xfe",
    "169.254.43518",
    "127.1",
    "0x7f000001",
    "010.0.0.1",
    "app.0x10",
    "999.1.1.1",
    # malformed
    "",
    "*.example.com",
    "10.0.0.0/8",
    "http://example.com",
    "-bad-.com",
    "exa mple.com",
    "bücher.de",
    "a" * 64 + ".com",
    "::1%lo",
    "fe80::1%eth0",
]

# Hosts the backend accepts for local_lab but the scanner refuses, by design:
# 6to4 / Teredo / NAT64 transition addresses are never lab addresses (ADR 0007).
SCANNER_STRICTER_FOR_LAB = {"2002:a00:1::1", "2002:c0a8:101::1"}
CORPUS += sorted(SCANNER_STRICTER_FOR_LAB)

# Both accept, but normalize differently: the backend collapses IPv4-mapped
# IPv6 to the IPv4 address (and stores that), the scanner keeps the mapped
# spelling. Stored scopes always use the IPv4 form, which both agree on; the
# scanner treating the mapped spelling as a different host is only stricter.
KNOWN_NORMALIZATION_DIFFERENCES = {"::ffff:10.0.0.1": ("10.0.0.1", "::ffff:10.0.0.1")}


def backend_accepts(host: str, environment: TargetEnvironment) -> str | None:
    try:
        return validate_host(host, environment)
    except DomainValidationError:
        return None


def scanner_accepts(host: str, *, lab_only: bool) -> str | None:
    try:
        return normalize_host(host, lab_only=lab_only)
    except ScopeViolation:
        return None


@pytest.mark.parametrize("host", CORPUS)
def test_lab_host_rules_agree(host: str) -> None:
    backend = backend_accepts(host, TargetEnvironment.LOCAL_LAB)
    scanner = scanner_accepts(host, lab_only=True)
    if host in SCANNER_STRICTER_FOR_LAB:
        assert backend is not None and scanner is None
        return
    if host in KNOWN_NORMALIZATION_DIFFERENCES:
        assert (backend, scanner) == KNOWN_NORMALIZATION_DIFFERENCES[host]
        assert scanner_accepts(backend or "", lab_only=True) == backend  # stored form agrees
        return
    assert backend == scanner, f"{host!r}: backend={backend!r} scanner={scanner!r}"


@pytest.mark.parametrize("host", CORPUS)
def test_scanner_never_accepts_what_the_backend_rejects(host: str) -> None:
    for environment, lab_only in (
        (TargetEnvironment.LOCAL_LAB, True),
        (TargetEnvironment.AUTHORIZED_EXTERNAL, False),
    ):
        if backend_accepts(host, environment) is None:
            assert scanner_accepts(host, lab_only=lab_only) is None, (host, environment)
