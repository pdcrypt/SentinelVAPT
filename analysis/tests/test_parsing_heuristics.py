import time

import pytest
from sentinel_analysis.heuristics import (
    error_markers_in,
    is_session_like_cookie,
    looks_like_directory_listing,
)
from sentinel_analysis.parsing import (
    csp_directives,
    frame_options_protective,
    has_version,
    is_html,
    is_nosniff,
    origin_key,
    parse_allow,
    parse_hsts,
)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://Lab.Test/", "http://lab.test:80"),
        ("https://lab.test:8443/a?b#c", "https://lab.test:8443"),
        ("https://lab.test/", "https://lab.test:443"),
        ("http://[::1]:8080/", "http://[::1]:8080"),
        ("ftp://lab.test/", None),
        ("http://lab.test:99999/", None),
        ("not a url", None),
        ("", None),
    ],
)
def test_origin_key(url: str, expected: str | None) -> None:
    assert origin_key(url) == expected


@pytest.mark.parametrize(
    ("value", "effective"),
    [
        ("max-age=31536000; includeSubDomains", True),
        ('max-age="300"', True),
        ("MAX-AGE=1", True),
        ("max-age=0", False),
        ("includeSubDomains", False),  # max-age is required
        ("max-age=abc", False),
        ("max-age=-1", False),
        ("max-age=1; max-age=2", False),  # duplicate directive: invalid
        ("max-age=1" + "9" * 50, False),  # absurdly long number
        ("", False),
        (";;;", False),
    ],
)
def test_hsts(value: str, effective: bool) -> None:
    assert parse_hsts(value).effective is effective


def test_csp_directives() -> None:
    parsed = csp_directives("default-src 'self'; FRAME-ANCESTORS 'none'; frame-ancestors *")
    assert parsed["frame-ancestors"] == ("'none'",)  # first occurrence wins
    assert "default-src" in parsed
    assert csp_directives("") == {}


@pytest.mark.parametrize(
    ("value", "protective"),
    [
        ("DENY", True),
        ("sameorigin", True),
        (" SAMEORIGIN ", True),
        ("ALLOW-FROM https://x", False),
        ("", False),
        ("garbage", False),
    ],
)
def test_frame_options(value: str, protective: bool) -> None:
    assert frame_options_protective(value) is protective


def test_small_parsers() -> None:
    assert is_nosniff(" NoSniff ") and not is_nosniff("sniff")
    assert parse_allow("GET, post ,PUT,, x-y, DELETE") == {"GET", "POST", "PUT", "DELETE"}
    assert has_version("nginx/1.25.3") and has_version("PHP/8.2") and has_version("4.0.30319")
    assert not has_version("nginx") and not has_version("Apache") and not has_version("v1")
    assert is_html("text/html; charset=utf-8") and is_html("application/xhtml+xml")
    assert not is_html("application/json") and not is_html(None)


def test_parsers_are_bounded_on_hostile_input() -> None:
    huge = "a" * 2_000_000
    started = time.monotonic()
    parse_hsts(huge + "max-age=1")
    csp_directives(";" * 1_000_000)
    has_version("1." * 1_000_000)
    parse_allow("," * 1_000_000)
    origin_key("http://" + huge)
    assert time.monotonic() - started < 1.0


# --- heuristics ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "PHPSESSID",
        "JSESSIONID",
        "ASP.NET_SessionId",
        "laravel_session",
        "ci_session",
        "connect.sid",
        "rack.session",
        "sessionid",
        "session",
        "SID",
        "_session_id",
        "ASPSESSIONIDQASCSDRA",
        "app_session",
        "my-sess",
        "x.sessid",
        "user_auth",
        "csrf_token",
        "app-jwt",
        "auth",
    ],
)
def test_session_like_names(name: str) -> None:
    assert is_session_like_cookie(name)


@pytest.mark.parametrize(
    "name", ["sidebar", "consider", "theme", "lang", "authority", "tokens", "sessions", "", "  "]
)
def test_not_session_like(name: str) -> None:
    """Whole tokens only: substrings never match."""
    assert not is_session_like_cookie(name)


def test_error_markers() -> None:
    text = 'Traceback (most recent call last):\n  File "x.py"\nSQLSTATE[42000]'
    assert error_markers_in(text) == ("python_traceback", "sql_error")
    assert error_markers_in("All good. Trace this route.") == ()


@pytest.mark.parametrize(
    ("title", "excerpt", "expected"),
    [
        ("Index of /files/", "", True),
        ("Directory listing for /", "", True),
        (None, "<html><head><title>Index of /backup</title>", True),
        ("Index of products", "", False),
        ("Home", "<p>Index of /x mentioned in text</p>", False),
        (None, "", False),
    ],
)
def test_directory_listing(title: str | None, excerpt: str, expected: bool) -> None:
    assert looks_like_directory_listing(title, excerpt) is expected
