"""Pure validation of target scope and authorization. No I/O, no database.

Hostnames are validated syntactically and by naming convention only; they are
not resolved here. DNS answers can change between now and scan time, so the
scanner re-checks resolved addresses on every request (Phase 2).
"""

import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

from app.core.errors import DomainValidationError
from app.models.enums import AuthorizationStatus, TargetEnvironment

DEFAULT_PORTS = {"http": 80, "https": 443}

# Hostnames accepted for local_lab targets without being IP literals: localhost,
# single-label names (e.g. docker compose service names) and reserved or
# conventionally private suffixes.
LAB_HOSTNAMES = frozenset({"localhost"})
LAB_SUFFIXES = (".localhost", ".local", ".test", ".internal", ".lan", ".home.arpa")

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
# A label that resolvers or URL parsers may read as part of an IPv4 address:
# decimal, octal (leading 0) or hex (0x...). inet_aton() accepts forms such as
# 0xa9fea9fe, 2852039166 or 0251.0376.0251.0376, and the WHATWG URL parser treats
# any host whose last label is numeric as IPv4. Such hosts are rejected outright
# rather than reasoned about, so only canonical dotted-decimal IPs get through
# (and those go through the IP rules).
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")
_FORBIDDEN_PATH_CHARS = re.compile(r"[\s?#\\]|[\x00-\x1f\x7f]")

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class Scope:
    base_url: str
    hosts: list[str]
    ports: list[int]
    path_prefixes: list[str]
    excluded_paths: list[str]


def _parse_ip(host: str) -> IPAddress | None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.scope_id is not None:
        # Zone IDs (fe80::1%eth0) name a local interface; they never belong in scope.
        raise DomainValidationError(f"'{host}': IPv6 zone IDs are not allowed")
    # Treat ::ffff:a.b.c.d as the IPv4 address it maps to, so it cannot be used
    # to sneak past the IPv4 rules below.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _validate_ip(ip: IPAddress, environment: TargetEnvironment, field: str) -> str:
    # ::1 sits inside a block Python labels "reserved", so loopback is exempted here.
    if ip.is_unspecified or ip.is_multicast or (ip.is_reserved and not ip.is_loopback):
        raise DomainValidationError(f"{ip} is not a valid target address", field=field)
    if ip.is_link_local:
        # Covers 169.254.0.0/16, including cloud metadata endpoints.
        raise DomainValidationError(
            f"{ip} is link-local; link-local addresses are never in scope", field=field
        )
    if environment is TargetEnvironment.LOCAL_LAB and not (ip.is_loopback or ip.is_private):
        raise DomainValidationError(
            f"{ip} is a public address; local_lab targets must use loopback or private "
            "addresses (use environment=authorized_external for other systems)",
            field=field,
        )
    return str(ip)


def _validate_hostname(host: str, environment: TargetEnvironment, field: str) -> str:
    labels = host.split(".")
    if len(host) > 253 or not all(_LABEL.match(label) for label in labels):
        raise DomainValidationError(f"'{host}' is not a valid hostname", field=field)
    if _NUMERIC_LABEL.match(labels[-1]):
        raise DomainValidationError(
            f"'{host}' could be interpreted as a numeric IP address; use a hostname or a "
            "dotted-decimal IP such as 10.0.0.5",
            field=field,
        )

    is_lab_name = host in LAB_HOSTNAMES or len(labels) == 1 or host.endswith(LAB_SUFFIXES)
    if environment is TargetEnvironment.LOCAL_LAB and not is_lab_name:
        raise DomainValidationError(
            f"'{host}' does not look like a lab hostname; local_lab targets must use "
            f"localhost, a single-label name, or one of {', '.join(LAB_SUFFIXES)} "
            "(use environment=authorized_external for other systems)",
            field=field,
        )
    return host


def validate_host(raw: str, environment: TargetEnvironment, field: str = "in_scope_hosts") -> str:
    """Return the normalized host, or raise DomainValidationError."""
    host = raw.strip().lower().rstrip(".")
    if not host:
        raise DomainValidationError("host must not be empty", field=field)
    if "*" in host:
        raise DomainValidationError("wildcard hosts are not allowed", field=field)
    if "/" in host:
        raise DomainValidationError(
            f"'{host}' looks like a URL or CIDR range; list individual hosts only",
            field=field,
        )
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    try:
        ip = _parse_ip(host)
    except DomainValidationError as exc:
        raise DomainValidationError(exc.message, field=field) from None
    if ip is not None:
        return _validate_ip(ip, environment, field)
    return _validate_hostname(host, environment, field)


def validate_path(raw: str, field: str) -> str:
    """Normalize a path prefix: absolute, no traversal, no trailing slash (except '/')."""
    if not raw.startswith("/") or raw.startswith("//"):
        raise DomainValidationError(f"'{raw}' must be an absolute path like /app", field=field)
    if _FORBIDDEN_PATH_CHARS.search(raw):
        raise DomainValidationError(
            f"'{raw}' contains whitespace, control characters, '?', '#' or '\\'", field=field
        )
    if ".." in raw.split("/"):
        raise DomainValidationError(f"'{raw}' must not contain '..'", field=field)
    return raw.rstrip("/") or "/"


def path_matches(path: str, prefix: str) -> bool:
    """True if path is the prefix or below it, on a segment boundary
    ('/app' matches '/app' and '/app/x', not '/application')."""
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


def _dedupe[T](items: Iterable[T]) -> list[T]:
    return list(dict.fromkeys(items))


def validate_scope(
    *,
    base_url: str,
    environment: TargetEnvironment,
    hosts: Sequence[str],
    ports: Sequence[int] | None,
    path_prefixes: Sequence[str],
    excluded_paths: Sequence[str],
) -> Scope:
    """Validate a target's scope as a whole and return its normalized form.

    `ports=None` means "only the base URL's port".
    """
    norm_hosts = _dedupe(validate_host(h, environment) for h in hosts)
    if not norm_hosts:
        raise DomainValidationError(
            "at least one in-scope host is required", field="in_scope_hosts"
        )
    norm_prefixes = _dedupe(validate_path(p, "in_scope_path_prefixes") for p in path_prefixes)
    if not norm_prefixes:
        raise DomainValidationError(
            "at least one in-scope path prefix is required", field="in_scope_path_prefixes"
        )
    norm_excluded = _dedupe(validate_path(p, "excluded_paths") for p in excluded_paths)

    parts = urlsplit(base_url.strip())
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise DomainValidationError("base_url must use http or https", field="base_url")
    if parts.username is not None or parts.password is not None:
        raise DomainValidationError("base_url must not contain credentials", field="base_url")
    if parts.query or parts.fragment:
        raise DomainValidationError(
            "base_url must not contain a query string or fragment", field="base_url"
        )
    try:
        explicit_port = parts.port
    except ValueError:
        raise DomainValidationError("base_url has an invalid port", field="base_url") from None
    if not parts.hostname:
        raise DomainValidationError("base_url must include a host", field="base_url")

    host = validate_host(parts.hostname, environment, field="base_url")
    if host not in norm_hosts:
        raise DomainValidationError(
            f"base_url host '{host}' must be listed in in_scope_hosts", field="base_url"
        )

    # `is None`, not falsiness: an explicit ":0" must not silently become the default.
    if explicit_port == 0:
        raise DomainValidationError("base_url port must be between 1 and 65535", field="base_url")
    port = explicit_port if explicit_port is not None else DEFAULT_PORTS[scheme]
    norm_ports = sorted(set(ports)) if ports is not None else [port]
    if not norm_ports or any(not 1 <= p <= 65535 for p in norm_ports):
        raise DomainValidationError("ports must be between 1 and 65535", field="allowed_ports")
    if port not in norm_ports:
        raise DomainValidationError(
            f"base_url port {port} must be listed in allowed_ports", field="base_url"
        )

    path = validate_path(parts.path or "/", "base_url")
    if not any(path_matches(path, p) for p in norm_prefixes):
        raise DomainValidationError(
            "base_url path must be inside an in_scope_path_prefix", field="base_url"
        )
    if any(path_matches(path, p) for p in norm_excluded):
        raise DomainValidationError("base_url path is excluded from scope", field="base_url")

    netloc = f"[{host}]" if ":" in host else host
    if explicit_port is not None and explicit_port != DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{explicit_port}"
    normalized_url = urlunsplit((scheme, netloc, parts.path or "/", "", ""))

    return Scope(
        base_url=normalized_url,
        hosts=norm_hosts,
        ports=norm_ports,
        path_prefixes=norm_prefixes,
        excluded_paths=norm_excluded,
    )


def validate_authorization_window(
    valid_from: datetime, valid_until: datetime, now: datetime
) -> None:
    if valid_until <= valid_from:
        raise DomainValidationError(
            "authorization valid_until must be after valid_from", field="authorization"
        )
    if valid_until <= now:
        raise DomainValidationError("authorization window has already ended", field="authorization")


def authorization_status(
    valid_from: datetime, valid_until: datetime, now: datetime
) -> AuthorizationStatus:
    if now < valid_from:
        return AuthorizationStatus.PENDING
    if now >= valid_until:
        return AuthorizationStatus.EXPIRED
    return AuthorizationStatus.ACTIVE
