"""HTML rendering (Jinja2) and the output policy check.

Escaping: the environment autoescapes everything, undefined values are errors
(StrictUndefined), templates run in Jinja2's immutable sandbox, and snapshot
data is only ever passed as data, never compiled as template source. Every
printed value also has control and bidirectional-override characters
replaced.

After rendering, the output is parsed and checked against an allowlist of tags
and attributes. Anything else (script, event handlers, style attributes,
external resources, links outside the allowlist) fails the render. This is a
second, independent line of defence behind escaping.
"""

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

import jinja2
from jinja2 import FileSystemLoader, StrictUndefined
from jinja2.sandbox import ImmutableSandboxedEnvironment
from markupsafe import Markup

from sentinel_reports.errors import HtmlPolicyViolation
from sentinel_reports.snapshot import SEVERITY_ORDER
from sentinel_reports.templates import Template
from sentinel_reports.version import __version__

HTML_RENDERER = f"sentinel-reports/{__version__} jinja2/{jinja2.__version__}"

# Reference links are only ever made to these sources (taxonomy and rule
# references). Everything else, including every target URL, is shown as text.
LINK_HOSTS = frozenset({"top10.owasp.org", "wstg.owasp.org", "cwe.mitre.org"})

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'none'"
)

ALLOWED_TAGS = frozenset(
    {
        "html", "head", "meta", "title", "style", "body", "header", "footer", "main",
        "section", "article", "nav", "div", "span", "p", "h1", "h2", "h3", "h4", "ul", "ol",
        "li", "table", "thead", "tbody", "tr", "th", "td", "caption", "dl", "dt", "dd",
        "code", "pre", "strong", "em", "small", "a", "br", "hr", "figure", "figcaption",
        "svg", "g", "rect", "text", "line",
    }
)  # fmt: skip
ALLOWED_ATTRIBUTES = frozenset(
    {
        "class", "id", "href", "lang", "charset", "name", "content", "http-equiv", "colspan",
        "rowspan", "scope", "role", "aria-label", "aria-hidden", "xmlns", "viewbox", "width",
        "height", "x", "y", "x1", "x2", "y1", "y2", "rx", "fill", "stroke", "text-anchor",
        "font-size", "dominant-baseline",
    }
)  # fmt: skip
ALLOWED_META_NAMES = frozenset({"generator", "dcterms.created", "dcterms.modified"})
FORBIDDEN_CSS = ("url(", "@import", "expression(", "javascript:", "@font-face")

# C0/C1 control characters (except tab and newline) and Unicode bidirectional
# controls could hide or visually reorder report text ("Trojan Source"-style);
# they are replaced in every printed value.
_UNSAFE_CHARACTERS = re.compile(
    "[\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f\\u061c\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]"
)
REPLACEMENT_CHARACTER = "�"


def _finalize(value: object) -> object:
    # Markup is template output (e.g. a macro's), whose data was already
    # finalized and escaped when it was printed; it must keep its type, or
    # autoescape would escape it a second time.
    if isinstance(value, Markup):
        return value
    if isinstance(value, str):
        return _UNSAFE_CHARACTERS.sub(REPLACEMENT_CHARACTER, value)
    return value


def link_allowed(url: object) -> bool:
    if not isinstance(url, str) or len(url) > 2048:
        return False
    parts = urlsplit(url)
    return parts.scheme == "https" and parts.hostname in LINK_HOSTS and not parts.username


def _format_datetime(value: object) -> str:
    if value is None:
        return "—"
    moment = datetime.fromisoformat(str(value)).astimezone(UTC)
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _w3c(value: object) -> str:
    """W3C date-time to the second, as PDF metadata expects."""
    return datetime.fromisoformat(str(value)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _label(value: object) -> str:
    text = str(value).replace("_", " ")
    return text[:1].upper() + text[1:]


def _environment(template: Template) -> ImmutableSandboxedEnvironment:
    env = ImmutableSandboxedEnvironment(
        loader=FileSystemLoader(str(template.path)),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        auto_reload=False,
        keep_trailing_newline=False,
        finalize=_finalize,
    )
    env.filters["dt"] = _format_datetime
    env.filters["w3c"] = _w3c
    env.filters["label"] = _label
    env.filters["short"] = lambda value: str(value)[:8]
    env.tests["allowed_link"] = link_allowed
    return env


def _chart(by_severity: Mapping[str, int]) -> list[dict[str, Any]]:
    top = max(by_severity.values(), default=0) or 1
    return [
        {"severity": s, "count": by_severity[s], "width": round(by_severity[s] * 300 / top)}
        for s in SEVERITY_ORDER
    ]


def render_html(
    template: Template,
    snapshot: Mapping[str, Any],
    derived: Mapping[str, Any],
    integrity: Mapping[str, Any],
) -> bytes:
    page = _environment(template).get_template("report.html.j2")
    html = page.render(
        r=snapshot,
        d=derived,
        integrity=integrity,
        chart=_chart(derived["by_severity"]),
        csp=CSP,
        severity_order=SEVERITY_ORDER,
    )
    check_html_policy(html)
    return html.encode("utf-8")


class _PolicyChecker(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_style = False
        self.violation: str | None = None

    def _fail(self, reason: str) -> None:
        if self.violation is None:
            self.violation = reason

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in ALLOWED_TAGS:
            self._fail(f"tag <{tag}>")
            return
        for name, value in attrs:
            if name not in ALLOWED_ATTRIBUTES:
                self._fail(f"attribute {name} on <{tag}>")
            elif name == "href" and not (
                tag == "a" and value is not None and (value.startswith("#") or link_allowed(value))
            ):
                self._fail(f"link on <{tag}>")
        attributes = dict(attrs)
        if tag == "meta":
            equiv = (attributes.get("http-equiv") or "").lower()
            if equiv and equiv != "content-security-policy":
                self._fail("meta http-equiv")
            if attributes.get("name") and attributes["name"] not in ALLOWED_META_NAMES:
                self._fail("meta name")
        self.in_style = tag == "style"

    handle_startendtag = handle_starttag

    def handle_endtag(self, tag: str) -> None:
        if tag == "style":
            self.in_style = False

    def handle_data(self, data: str) -> None:
        if self.in_style and any(token in data.lower() for token in FORBIDDEN_CSS):
            self._fail("stylesheet content")

    def handle_pi(self, data: str) -> None:
        self._fail("processing instruction")


def check_html_policy(html: str) -> None:
    checker = _PolicyChecker()
    checker.feed(html)
    checker.close()
    if checker.violation is not None:
        raise HtmlPolicyViolation(checker.violation)
