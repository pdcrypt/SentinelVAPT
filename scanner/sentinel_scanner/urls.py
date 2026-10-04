"""URL joining that behaves the same on every supported Python version.

Up to Python 3.13, urllib.parse.urljoin is built on urlparse/urlunparse, which
treat ";..." in the last path segment as "parameters" and silently drop an
empty parameter list: urljoin("http://a/b", "x;") == "http://a/x" and
urljoin("http://a/b", "/x;?q=1") == "http://a/x?q=1". Python 3.14 joins with
urlsplit semantics and keeps the reference literal ("http://a/x;").

The scanner must record and request exactly what a page referenced, on every
Python version, so on older versions every ";" is swapped for a placeholder
character that occurs in neither URL (the standard library then sees no
parameters), joined, and swapped back. The result equals Python 3.14's urljoin.
"""

import sys
from urllib.parse import urljoin

# Private-use code points, never meaningful in URLs; the first one absent from
# both inputs is used, so the swap is always reversible.
_PLACEHOLDERS = tuple(chr(cp) for cp in range(0xE000, 0xE100))


def _join_literal_params(base: str, url: str) -> str:
    """urljoin with ";" treated as an ordinary path character (3.14 semantics)."""
    if ";" not in base and ";" not in url:
        return urljoin(base, url)
    placeholder = next(p for p in _PLACEHOLDERS if p not in base and p not in url)
    joined = urljoin(base.replace(";", placeholder), url.replace(";", placeholder))
    return joined.replace(placeholder, ";")


def join_url(base: str, url: str) -> str:
    if sys.version_info >= (3, 14):
        return urljoin(base, url)
    return _join_literal_params(base, url)
