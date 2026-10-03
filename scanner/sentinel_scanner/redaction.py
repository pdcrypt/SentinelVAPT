"""Redaction of sensitive values before anything leaves the scanner.

Applied to every header, URL and body excerpt that goes into results or
evidence. Errs on the side of redacting: a hidden value costs little, a leaked
session token or key in a report is a real problem.
"""

import re
from collections.abc import Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

_ALWAYS_SENSITIVE_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "set-cookie", "www-authenticate"}
)
_SENSITIVE_NAME_PARTS = (
    "token",
    "secret",
    "key",
    "session",
    "auth",
    "csrf",
    "xsrf",
    "password",
    "passwd",
    "pwd",
    "signature",
    "sig",
    "credential",
    "jwt",
)
# Header names that contain a sensitive word but carry no secret.
_HARMLESS_HEADERS = frozenset({"keep-alive", "sec-websocket-key"})

_BODY_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        REDACTED,
    ),
    ("jwt", re.compile(r"\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*"), REDACTED),
    ("bearer", re.compile(r"(?i)\b(bearer\s+)[\w\-.~+/]{8,}=*"), r"\1" + REDACTED),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (
        "hidden_input_value",
        re.compile(
            r"(?i)(<input\b[^>]*\bname\s*=\s*[\"']?[^\"'\s>]*(?:token|csrf|xsrf|secret|key|"
            r"session|nonce|auth)[^\"'\s>]*[\"']?[^>]*?\bvalue\s*=\s*)([\"'])(.*?)\2"
        ),
        r"\1\2" + REDACTED + r"\2",
    ),
    (
        "hidden_input_value",
        re.compile(
            r"(?i)(<input\b[^>]*?\bvalue\s*=\s*)([\"'])(.*?)\2([^>]*\bname\s*=\s*[\"']?[^\"'\s>]*"
            r"(?:token|csrf|xsrf|secret|key|session|nonce|auth))"
        ),
        r"\1\2" + REDACTED + r"\2\4",
    ),
    (
        "assignment",
        re.compile(
            r"(?i)\b((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
            r"client[_-]?secret|session[_-]?id)[\"']?\s*[:=]\s*[\"']?)([^\"'\s&<>,;]{3,})"
        ),
        r"\1" + REDACTED,
    ),
)


def is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in _HARMLESS_HEADERS:
        return False
    return lowered in _ALWAYS_SENSITIVE_HEADERS or any(
        part in lowered for part in _SENSITIVE_NAME_PARTS
    )


def _redact_set_cookie(value: str) -> str:
    # Keep the cookie name and attributes (evidence of its security flags),
    # drop the value.
    first, _, attributes = value.partition(";")
    name = first.split("=", 1)[0].strip()
    return f"{name}={REDACTED}" + (f";{attributes}" if attributes else "")


def redact_headers(
    headers: Sequence[tuple[str, str]],
) -> tuple[list[tuple[str, str]], list[str]]:
    """Return (redacted headers, names of headers whose values were redacted)."""
    result: list[tuple[str, str]] = []
    redacted: list[str] = []
    for name, value in headers:
        lowered = name.lower()
        if lowered == "set-cookie":
            result.append((name, _redact_set_cookie(value)))
            redacted.append(name)
        elif is_sensitive_name(name):
            result.append((name, REDACTED))
            redacted.append(name)
        else:
            result.append((name, value))
    return result, redacted


def redact_url(url: str) -> tuple[str, bool]:
    """Redact credentials and sensitive query values. Returns (url, changed)."""
    parts = urlsplit(url)
    changed = False
    netloc = parts.netloc
    if "@" in netloc:
        netloc = f"{REDACTED}@{netloc.rsplit('@', 1)[1]}"
        changed = True
    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        safe = []
        for key, value in pairs:
            if value and is_sensitive_name(key):
                safe.append((key, REDACTED))
                changed = True
            else:
                safe.append((key, value))
        if changed:
            query = urlencode(safe, safe="[]")
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment)), changed


def redact_text(text: str) -> tuple[str, list[str]]:
    """Redact secrets from free text (body excerpts). Returns (text, kinds found)."""
    kinds: list[str] = []
    for kind, pattern, replacement in _BODY_PATTERNS:
        text, count = pattern.subn(replacement, text)
        if count and kind not in kinds:
            kinds.append(kind)
    return text, kinds
