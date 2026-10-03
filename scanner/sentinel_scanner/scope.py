"""Request-time scope enforcement. Pure and offline.

ScopePolicy answers one question before every request: may this exact URL be
requested? It re-validates the scope it is given rather than trusting the
caller, and canonicalizes paths so that what is checked is exactly what is
sent (the transport sends the canonical form).
"""

import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

from sentinel_scanner.errors import ScopeViolation
from sentinel_scanner.netaddr import IPAddress, address_problem, parse_ip

DEFAULT_PORTS = {"http": 80, "https": 443}

LAB_HOSTNAMES = frozenset({"localhost"})
LAB_SUFFIXES = (".localhost", ".local", ".test", ".internal", ".lan", ".home.arpa")

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
# A last label that resolvers or URL parsers may read as (part of) an IPv4
# address: decimal, octal or hex. See backend/app/services/scope.py.
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PCT = re.compile(r"%([0-9A-Fa-f]{2})")
# Encoded '/', '\' and NUL change how servers split or terminate paths.
_AMBIGUOUS_ENCODING = re.compile(r"%(2f|5c|00)", re.IGNORECASE)
_FORBIDDEN_PATH_CHARS = re.compile(r"[\s\\]|[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class CheckedUrl:
    """A URL that passed the scope check, in the canonical form that is sent."""

    scheme: str
    host: str
    port: int
    path: str
    query: str

    @property
    def url(self) -> str:
        return urlunsplit((self.scheme, self.netloc, self.path, self.query, ""))

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        if self.port == DEFAULT_PORTS[self.scheme]:
            return host
        return f"{host}:{self.port}"

    @property
    def target(self) -> str:
        """Request target for the HTTP request line."""
        return f"{self.path}?{self.query}" if self.query else self.path


def _violation(code: str, message: str, url: str | None = None) -> ScopeViolation:
    return ScopeViolation(code, message, url)


def normalize_host(raw: str, *, lab_only: bool) -> str:
    """Validate and normalize a scope host (same rules as the backend)."""
    host = raw.strip().lower().rstrip(".")
    if not host or "*" in host or "/" in host or "%" in host:
        raise _violation("invalid_host", f"'{raw}' is not an exact host")
    ip = parse_ip(host)
    if ip is not None:
        problem = address_problem(ip, lab_only=lab_only)
        if problem:
            raise _violation("forbidden_address", f"{ip}: {problem}")
        return str(ip)
    labels = host.split(".")
    if len(host) > 253 or not all(_LABEL.match(label) for label in labels):
        raise _violation("invalid_host", f"'{raw}' is not a valid hostname")
    if _NUMERIC_LABEL.match(labels[-1]):
        raise _violation("numeric_host", f"'{raw}' could be read as a numeric IP address")
    if lab_only and not (host in LAB_HOSTNAMES or len(labels) == 1 or host.endswith(LAB_SUFFIXES)):
        raise _violation("not_lab_host", f"'{raw}' is not a lab hostname")
    return host


def canonical_path(raw: str) -> str:
    """Canonicalize a URL path so scope checks and the request agree.

    - rejects encoded '/', '\\' and NUL, backslashes and control characters
    - decodes percent-encoded unreserved characters (so %2e becomes '.')
    - upper-cases remaining percent-escapes
    - collapses repeated slashes
    - removes dot segments (RFC 3986 5.2.4)
    """
    path = raw or "/"
    if not path.startswith("/"):
        raise _violation("invalid_path", "path must be absolute")
    if _AMBIGUOUS_ENCODING.search(path):
        raise _violation("ambiguous_path", "path contains an encoded '/', '\\' or NUL")
    if _FORBIDDEN_PATH_CHARS.search(path):
        raise _violation("invalid_path", "path contains whitespace, '\\' or control characters")

    def decode(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else f"%{match.group(1).upper()}"

    path = _PCT.sub(decode, path)
    path = re.sub(r"/{2,}", "/", path)

    output: list[str] = []
    for segment in path.split("/")[1:]:
        if segment == ".":
            continue
        if segment == "..":
            if output:
                output.pop()
            continue
        output.append(segment)
    trailing = path.endswith(("/", "/.", "/.."))
    result = "/" + "/".join(output)
    if trailing and not result.endswith("/"):
        result += "/"
    return result


def _match_key(path: str) -> str:
    # Servers such as Tomcat ignore ';params' in segments; compare without them.
    return "/".join(segment.split(";", 1)[0] for segment in path.split("/")) or "/"


def path_matches(path: str, prefix: str) -> bool:
    """True if path is prefix or below it, on a segment boundary."""
    if prefix == "/":
        return True
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


class ScopePolicy:
    """Immutable allowlist built from an authorization's scope snapshot."""

    def __init__(
        self,
        *,
        hosts: tuple[str, ...],
        ports: tuple[int, ...],
        path_prefixes: tuple[str, ...],
        excluded_paths: tuple[str, ...],
        lab_only: bool,
    ) -> None:
        if not hosts or not ports or not path_prefixes:
            raise _violation("empty_scope", "scope must list hosts, ports and path prefixes")
        if any(not 1 <= p <= 65535 for p in ports):
            raise _violation("invalid_port", "ports must be between 1 and 65535")
        self.lab_only = lab_only
        self.hosts = frozenset(normalize_host(h, lab_only=lab_only) for h in hosts)
        self.ports = frozenset(ports)
        self.path_prefixes = tuple(canonical_path(p) for p in path_prefixes)
        # Exclusions are compared case-insensitively: a case-insensitive server
        # would otherwise serve /ADMIN for an excluded /admin.
        self.excluded_keys = tuple(_match_key(canonical_path(p)).lower() for p in excluded_paths)

    def check_url(self, url: str) -> CheckedUrl:
        """Return the canonical URL to request, or raise ScopeViolation."""
        try:
            parts: SplitResult = urlsplit(url.strip())
            port = parts.port
        except ValueError:
            raise _violation("invalid_url", "URL could not be parsed", url) from None
        scheme = parts.scheme.lower()
        if scheme not in DEFAULT_PORTS:
            raise _violation("scheme_not_allowed", f"scheme '{scheme}' is not allowed", url)
        if parts.username is not None or parts.password is not None:
            raise _violation("credentials_in_url", "URLs with credentials are not allowed", url)
        if not parts.hostname:
            raise _violation("invalid_url", "URL has no host", url)
        try:
            host = normalize_host(parts.hostname, lab_only=self.lab_only)
        except ScopeViolation as exc:
            raise _violation(exc.code, exc.message, url) from None
        if host not in self.hosts:
            raise _violation("host_out_of_scope", f"host '{host}' is not in scope", url)
        if port == 0:
            raise _violation("port_not_allowed", "port 0 is not allowed", url)
        effective_port = port if port is not None else DEFAULT_PORTS[scheme]
        if effective_port not in self.ports:
            raise _violation("port_not_allowed", f"port {effective_port} is not in scope", url)
        try:
            path = canonical_path(parts.path)
        except ScopeViolation as exc:
            raise _violation(exc.code, exc.message, url) from None
        key = _match_key(path)
        if not any(path_matches(key, prefix) for prefix in self.path_prefixes):
            raise _violation("path_out_of_scope", f"path '{path}' is outside the scope", url)
        if any(path_matches(key.lower(), excluded) for excluded in self.excluded_keys):
            raise _violation("path_excluded", f"path '{path}' is excluded from scope", url)
        return CheckedUrl(scheme, host, effective_port, path, parts.query)

    def check_address(self, ip: IPAddress, host: str) -> None:
        """Raise ScopeViolation unless a resolved address may be contacted."""
        problem = address_problem(ip, lab_only=self.lab_only)
        if problem:
            raise _violation(
                "forbidden_address", f"'{host}' resolved to {ip}, which is blocked: {problem}"
            )
