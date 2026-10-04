"""Bounded parsers for untrusted header values and URLs.

Every input is length-capped before parsing. No regular expression here has
nested or overlapping quantifiers, so none can backtrack catastrophically.
Unparsable input yields a conservative "unknown" result, never an exception.
"""

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URL = 4096
MAX_HEADER_VALUE = 4096
MAX_DIRECTIVES = 64

DEFAULT_PORTS = {"http": 80, "https": 443}

# Digits, a dot, digits (repeated): "1.25.3", "8.2", "4.0.30319". Linear-time.
_VERSION = re.compile(r"\d+(?:\.\d+)+")
_METHOD_TOKEN = re.compile(r"^[A-Z]{1,16}$")


def clip(value: str, limit: int = MAX_HEADER_VALUE) -> str:
    return value[:limit]


def origin_key(url: str) -> str | None:
    """Canonical "scheme://host:port" (default port explicit), or None."""
    try:
        parts = urlsplit(clip(url, MAX_URL))
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS or not parts.hostname:
        return None
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}:{port if port is not None else DEFAULT_PORTS[scheme]}"


def scheme_of(url: str) -> str:
    try:
        return urlsplit(clip(url, MAX_URL)).scheme.lower()
    except ValueError:
        return ""


@dataclass(frozen=True)
class Hsts:
    present: bool
    valid: bool
    max_age: int | None

    @property
    def effective(self) -> bool:
        return self.valid and self.max_age is not None and self.max_age > 0


def parse_hsts(value: str) -> Hsts:
    """RFC 6797: max-age is required; a directive appearing twice is invalid."""
    seen: set[str] = set()
    max_age: int | None = None
    for raw in clip(value).split(";")[:MAX_DIRECTIVES]:
        name, _, arg = raw.strip().partition("=")
        name = name.strip().lower()
        if not name:
            continue
        if name in seen:
            return Hsts(present=True, valid=False, max_age=None)
        seen.add(name)
        if name == "max-age":
            arg = arg.strip().strip('"')
            if not arg.isdigit() or len(arg) > 12:
                return Hsts(present=True, valid=False, max_age=None)
            max_age = int(arg)
    return Hsts(present=True, valid=max_age is not None, max_age=max_age)


def csp_directives(value: str) -> dict[str, tuple[str, ...]]:
    """Directive name -> source tokens. First occurrence wins (as in browsers)."""
    directives: dict[str, tuple[str, ...]] = {}
    for raw in clip(value).split(";")[:MAX_DIRECTIVES]:
        tokens = raw.split()
        if tokens:
            name = tokens[0].lower()
            directives.setdefault(name, tuple(tokens[1:16]))
    return directives


def frame_options_protective(value: str) -> bool:
    """Only DENY and SAMEORIGIN are honoured by current browsers; ALLOW-FROM
    and unknown values are treated as not protective."""
    return clip(value, 64).strip().upper() in {"DENY", "SAMEORIGIN"}


def is_nosniff(value: str) -> bool:
    return clip(value, 64).strip().lower() == "nosniff"


def parse_allow(value: str) -> frozenset[str]:
    methods = set()
    for token in clip(value).split(",")[:MAX_DIRECTIVES]:
        token = token.strip().upper()
        if _METHOD_TOKEN.match(token):
            methods.add(token)
    return frozenset(methods)


def has_version(value: str) -> bool:
    return _VERSION.search(clip(value, 256)) is not None


def is_html(content_type: str | None) -> bool:
    if not content_type:
        return False
    mime = clip(content_type, 256).split(";", 1)[0].strip().lower()
    return mime in {"text/html", "application/xhtml+xml"}
