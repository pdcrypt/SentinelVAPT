from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.core.errors import DomainValidationError
from app.models.enums import AuthorizationStatus, TargetEnvironment
from app.services.scope import (
    authorization_status,
    path_matches,
    validate_authorization_window,
    validate_host,
    validate_path,
    validate_scope,
)

LAB = TargetEnvironment.LOCAL_LAB
EXTERNAL = TargetEnvironment.AUTHORIZED_EXTERNAL


# --- Hosts ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("localhost", "localhost"),
        ("Juice-Shop", "juice-shop"),  # single-label (docker service name)
        ("app.test.", "app.test"),  # trailing dot stripped
        ("dvwa.local", "dvwa.local"),
        ("127.0.0.1", "127.0.0.1"),
        ("10.1.2.3", "10.1.2.3"),
        ("192.168.0.10", "192.168.0.10"),
        ("[::1]", "::1"),
        ("fd00::1", "fd00::1"),
    ],
)
def test_lab_hosts_accepted(raw: str, expected: str) -> None:
    assert validate_host(raw, LAB) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "example.com",  # public-looking hostname
        "8.8.8.8",  # public IP
        "::ffff:8.8.8.8",  # public IPv4 hidden in IPv6
    ],
)
def test_lab_rejects_public_hosts(raw: str) -> None:
    with pytest.raises(DomainValidationError, match="local_lab"):
        validate_host(raw, LAB)


@pytest.mark.parametrize("raw", ["example.com", "8.8.8.8", "10.0.0.5", "localhost"])
def test_external_accepts_regular_hosts(raw: str) -> None:
    assert validate_host(raw, EXTERNAL) == raw


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "empty"),
        ("*.example.com", "wildcard"),
        ("*", "wildcard"),
        ("10.0.0.0/8", "CIDR"),
        ("http://example.com", "URL"),
        ("169.254.169.254", "link-local"),  # cloud metadata endpoint
        ("::ffff:169.254.169.254", "link-local"),
        ("fe80::1", "link-local"),
        ("0.0.0.0", "not a valid target"),  # noqa: S104  # input under test, not a bind
        ("224.0.0.1", "not a valid target"),
        ("-bad-.com", "valid hostname"),
        ("exa mple.com", "valid hostname"),
        ("bücher.de", "valid hostname"),  # IDN must be punycode
        ("999.1.1.1", "numeric IP"),
        ("a" * 64 + ".com", "valid hostname"),
    ],
)
@pytest.mark.parametrize("environment", [LAB, EXTERNAL])
def test_invalid_hosts_rejected(raw: str, message: str, environment: TargetEnvironment) -> None:
    with pytest.raises(DomainValidationError, match=message):
        validate_host(raw, environment)


# Hostname spellings that the OS resolver (inet_aton) or URL parsers read as IPv4.
# Each of these is 169.254.169.254, the cloud metadata address, in disguise.
METADATA_SPELLINGS = [
    "0xa9fea9fe",  # single hex number
    "0xA9FEA9FE",
    "2852039166",  # single decimal number
    "0xa9.0xfe.0xa9.0xfe",  # hex per octet
    "0251.0376.0251.0376",  # octal per octet
    "169.254.43518",  # a.b.c with 16-bit last part
    "169.16689662",  # a.b with 24-bit last part
    "0xa9.254.169.254",  # mixed
]


@pytest.mark.parametrize("raw", METADATA_SPELLINGS)
@pytest.mark.parametrize("environment", [LAB, EXTERNAL])
def test_numeric_ip_spellings_rejected(raw: str, environment: TargetEnvironment) -> None:
    with pytest.raises(DomainValidationError, match="numeric IP"):
        validate_host(raw, environment)


@pytest.mark.parametrize("raw", ["0x7f000001", "017700000001", "127.1", "010.0.0.1", "app.0x10"])
def test_other_numeric_spellings_rejected(raw: str) -> None:
    # Loopback/private in disguise, leading-zero octets, and a numeric last label.
    with pytest.raises(DomainValidationError, match="numeric IP"):
        validate_host(raw, EXTERNAL)


@pytest.mark.parametrize("raw", ["0x1.example.com", "x0.test", "web01", "1password.com"])
def test_hostnames_with_numeric_looking_labels_still_allowed(raw: str) -> None:
    # Only a numeric *last* label makes a host parseable as IPv4.
    assert validate_host(raw, EXTERNAL) == raw


@pytest.mark.parametrize("raw", ["fe80::1%eth0", "::1%lo", "[::1%lo]", "fd00::1%1"])
@pytest.mark.parametrize("environment", [LAB, EXTERNAL])
def test_ipv6_zone_ids_rejected(raw: str, environment: TargetEnvironment) -> None:
    with pytest.raises(DomainValidationError, match="zone ID") as exc:
        validate_host(raw, environment)
    assert exc.value.field == "in_scope_hosts"


# --- Paths ------------------------------------------------------------------------


@pytest.mark.parametrize(("raw", "expected"), [("/", "/"), ("/app/", "/app"), ("/a/b", "/a/b")])
def test_valid_paths(raw: str, expected: str) -> None:
    assert validate_path(raw, "f") == expected


@pytest.mark.parametrize(
    "raw", ["app", "//evil.com", "/a/../b", "/a?x=1", "/a#b", "/a b", "/a\\b", "/a\x00"]
)
def test_invalid_paths(raw: str) -> None:
    with pytest.raises(DomainValidationError):
        validate_path(raw, "f")


@pytest.mark.parametrize(
    ("path", "prefix", "expected"),
    [
        ("/anything", "/", True),
        ("/app", "/app", True),
        ("/app/x", "/app", True),
        ("/application", "/app", False),  # segment boundary
        ("/", "/app", False),
    ],
)
def test_path_matches(path: str, prefix: str, expected: bool) -> None:
    assert path_matches(path, prefix) is expected


# --- Whole scope ------------------------------------------------------------------


def _scope(**overrides: Any) -> Any:
    args: dict[str, Any] = {
        "base_url": "http://juice-shop:3000/",
        "environment": LAB,
        "hosts": ["juice-shop"],
        "ports": None,
        "path_prefixes": ["/"],
        "excluded_paths": [],
    }
    args.update(overrides)
    return validate_scope(**args)


def test_scope_defaults_ports_to_base_url_port() -> None:
    assert _scope().ports == [3000]
    assert _scope(base_url="https://juice-shop/", ports=None).ports == [443]


def test_scope_normalizes_url_and_dedupes() -> None:
    scope = _scope(
        base_url="HTTP://JUICE-SHOP:80/app",
        hosts=["juice-shop", "JUICE-SHOP", "dvwa"],
        ports=[80, 8080, 80],
        path_prefixes=["/app/", "/app"],
    )
    assert scope.base_url == "http://juice-shop/app"  # default port dropped
    assert scope.hosts == ["juice-shop", "dvwa"]
    assert scope.ports == [80, 8080]
    assert scope.path_prefixes == ["/app"]


def test_explicit_port_is_distinguished_from_omitted_port() -> None:
    # Omitted: scheme default. Explicit default port: same scope, normalized away.
    assert _scope(base_url="http://juice-shop/").ports == [80]
    explicit = _scope(base_url="http://juice-shop:80/")
    assert explicit.ports == [80]
    assert explicit.base_url == "http://juice-shop/"
    # Explicit non-default port is kept in the URL and is what must be allowed.
    assert _scope(base_url="https://juice-shop:8443/").base_url == "https://juice-shop:8443/"
    # Empty port after the colon means "omitted".
    assert _scope(base_url="http://juice-shop:/").ports == [80]


def test_scope_ipv6_base_url() -> None:
    scope = _scope(base_url="http://[::1]:8080/", hosts=["::1"])
    assert scope.base_url == "http://[::1]:8080/"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"base_url": "ftp://juice-shop/"}, "http or https"),
        ({"base_url": "javascript:alert(1)"}, "http or https"),
        ({"base_url": "http://u:p@juice-shop:3000/"}, "credentials"),
        ({"base_url": "http://juice-shop:3000/?q=1"}, "query"),
        ({"base_url": "http://juice-shop:3000/#x"}, "fragment"),
        ({"base_url": "http://juice-shop:99999/"}, "invalid port"),
        ({"base_url": "http://juice-shop:0/"}, "between 1 and 65535"),
        ({"base_url": "http://juice-shop:0/", "ports": [80]}, "between 1 and 65535"),
        ({"base_url": "http:///path"}, "include a host"),
        ({"base_url": "http://dvwa/"}, "must be listed in in_scope_hosts"),
        ({"ports": [8080]}, "must be listed in allowed_ports"),
        ({"path_prefixes": ["/api"]}, "inside an in_scope_path_prefix"),
        ({"excluded_paths": ["/"]}, "excluded"),
        ({"hosts": []}, "at least one in-scope host"),
        ({"path_prefixes": []}, "at least one in-scope path"),
    ],
)
def test_scope_rejections(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(DomainValidationError, match=message):
        _scope(**overrides)


# --- Authorization ----------------------------------------------------------------

NOW = datetime(2026, 10, 4, 12, tzinfo=UTC)
DAY = timedelta(days=1)


def test_authorization_window_valid() -> None:
    validate_authorization_window(NOW - DAY, NOW + DAY, NOW)
    validate_authorization_window(NOW + DAY, NOW + 2 * DAY, NOW)  # future window is fine


@pytest.mark.parametrize(
    ("valid_from", "valid_until", "message"),
    [
        (NOW + DAY, NOW + DAY, "after valid_from"),
        (NOW + DAY, NOW, "after valid_from"),
        (NOW - 2 * DAY, NOW - DAY, "already ended"),
        (NOW - DAY, NOW, "already ended"),
    ],
)
def test_authorization_window_invalid(
    valid_from: datetime, valid_until: datetime, message: str
) -> None:
    with pytest.raises(DomainValidationError, match=message):
        validate_authorization_window(valid_from, valid_until, NOW)


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (NOW - timedelta(seconds=1), AuthorizationStatus.PENDING),
        (NOW, AuthorizationStatus.ACTIVE),
        (NOW + DAY - timedelta(seconds=1), AuthorizationStatus.ACTIVE),
        (NOW + DAY, AuthorizationStatus.EXPIRED),
    ],
)
def test_authorization_status_boundaries(now: datetime, expected: AuthorizationStatus) -> None:
    assert authorization_status(NOW, NOW + DAY, now) is expected
