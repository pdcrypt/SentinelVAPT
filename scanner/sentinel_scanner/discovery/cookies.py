"""Set-Cookie parsing: names and security attributes only, never values."""

from sentinel_scanner.models import CookieObservation


def parse_set_cookie(header_value: str) -> CookieObservation | None:
    first, *attributes = header_value.split(";")
    name, sep, _value = first.partition("=")
    name = name.strip()
    if not sep or not name:
        return None
    secure = http_only = has_expiry = False
    same_site = domain = path = None
    for attribute in attributes:
        key, _, val = attribute.strip().partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key == "secure":
            secure = True
        elif key == "httponly":
            http_only = True
        elif key == "samesite":
            same_site = val or None
        elif key == "domain":
            domain = val or None
        elif key == "path":
            path = val or None
        elif key in ("expires", "max-age"):
            has_expiry = True
    return CookieObservation(
        name=name[:200],
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        domain=domain,
        path=path,
        has_expiry=has_expiry,
    )
