"""URL joining is identical on every supported Python version (see urls.py)."""

import itertools
import sys
from urllib.parse import urljoin

import pytest

from sentinel_scanner.urls import _join_literal_params, join_url

BASE = "http://lab.test/sitemap.xml"

# Python 3.14 urljoin results: ";" is kept literally (3.13's urljoin drops an
# empty parameter list, e.g. "x;" -> "http://lab.test/x").
CASES = [
    ("&b;", "http://lab.test/&b;"),
    ("x;", "http://lab.test/x;"),
    ("x;y", "http://lab.test/x;y"),
    ("/p;", "http://lab.test/p;"),
    ("/p;q", "http://lab.test/p;q"),
    ("a/b;/c;", "http://lab.test/a/b;/c;"),
    (";", "http://lab.test/;"),
    ("/x;?q=1", "http://lab.test/x;?q=1"),
    ("/x;#f", "http://lab.test/x;#f"),
    ("x;;", "http://lab.test/x;;"),
    ("http://other/z;", "http://other/z;"),
    ("../up;/x", "http://lab.test/up;/x"),
    ("\ue000;", "http://lab.test/\ue000;"),  # the first placeholder is in the input
]


@pytest.mark.parametrize(("ref", "expected"), CASES)
def test_semicolons_are_kept_literally(ref: str, expected: str) -> None:
    assert join_url(BASE, ref) == expected
    assert _join_literal_params(BASE, ref) == expected


def test_base_parameters_are_kept_literally() -> None:
    assert join_url("http://lab.test/a;v=1/b;", "c") == "http://lab.test/a;v=1/c"
    assert join_url("http://lab.test/a;", "") == "http://lab.test/a;"
    assert join_url("http://lab.test/a;?q", "#f") == "http://lab.test/a;?q#f"


@pytest.mark.skipif(sys.version_info < (3, 14), reason="compares with 3.14's urljoin")
def test_fallback_matches_python_3_14_urljoin() -> None:
    bases = [
        "http://lab.test/",
        "http://lab.test/a/b",
        "http://lab.test/a;p/b;q",
        "https://h:8443/x/",
    ]
    parts = ["", ";", "a", "/", "..", ".", "?q=1", "#f", ";p", "b;c"]
    for base in bases:
        for combo in itertools.product(parts, repeat=3):
            ref = "".join(combo)
            assert _join_literal_params(base, ref) == urljoin(base, ref), (base, ref)
