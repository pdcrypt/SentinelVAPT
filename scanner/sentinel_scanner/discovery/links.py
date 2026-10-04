"""Link extraction from HTML, robots.txt and sitemap.xml.

Parses untrusted content with the standard library only. No scripts are run,
no forms are submitted, and the number of links taken from one document is
capped.
"""

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urldefrag

from sentinel_scanner.models import EndpointSource
from sentinel_scanner.urls import join_url

MAX_LINKS_PER_DOCUMENT = 1000
MAX_TITLE_LENGTH = 300
_IGNORED_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "about:", "blob:", "ftp:")

# (tag, attribute) -> source
_LINK_ATTRIBUTES: dict[tuple[str, str], EndpointSource] = {
    ("a", "href"): EndpointSource.LINK,
    ("area", "href"): EndpointSource.LINK,
    ("iframe", "src"): EndpointSource.FRAME,
    ("frame", "src"): EndpointSource.FRAME,
    ("script", "src"): EndpointSource.SCRIPT,
    ("img", "src"): EndpointSource.IMAGE,
}


@dataclass(frozen=True)
class ExtractedLink:
    url: str  # absolute, fragment removed
    source: EndpointSource
    method: str = "GET"  # forms may declare POST; recorded, never submitted


@dataclass
class HtmlDocument:
    links: list[ExtractedLink] = field(default_factory=list)
    title: str | None = None
    generator: str | None = None


class _Extractor(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = page_url
        self.base_seen = False
        self.doc = HtmlDocument()
        self._in_title = False
        self._title_parts: list[str] = []

    def _add(self, raw: str | None, source: EndpointSource, method: str = "GET") -> None:
        if raw is None or len(self.doc.links) >= MAX_LINKS_PER_DOCUMENT:
            return
        value = raw.strip()
        if not value or value.lower().startswith(_IGNORED_SCHEMES) or value.startswith("#"):
            return
        absolute, _ = urldefrag(join_url(self.base_url, value))
        self.doc.links.append(ExtractedLink(absolute, source, method))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "base" and not self.base_seen and attributes.get("href"):
            # Only the first <base> counts, as in browsers. Links resolved
            # against it are still scope-checked before any request.
            self.base_url = join_url(self.base_url, attributes["href"] or "")
            self.base_seen = True
        elif tag == "link":
            rel = (attributes.get("rel") or "").lower()
            source = EndpointSource.STYLESHEET if "stylesheet" in rel else EndpointSource.LINK
            self._add(attributes.get("href"), source)
        elif tag == "form":
            method = (attributes.get("method") or "GET").upper()
            # A form without action submits to the page itself.
            self._add(attributes.get("action") or self.base_url, EndpointSource.FORM, method)
        elif tag == "meta" and (attributes.get("name") or "").lower() == "generator":
            self.doc.generator = (attributes.get("content") or "")[:200] or None
        elif tag == "title":
            self._in_title = True
        else:
            for attr in ("href", "src"):
                link_source = _LINK_ATTRIBUTES.get((tag, attr))
                if link_source is not None:
                    self._add(attributes.get(attr), link_source)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and sum(map(len, self._title_parts)) < MAX_TITLE_LENGTH:
            self._title_parts.append(data)

    def result(self) -> HtmlDocument:
        title = " ".join("".join(self._title_parts).split())[:MAX_TITLE_LENGTH]
        self.doc.title = title or None
        return self.doc


def extract_html(html: str, page_url: str) -> HtmlDocument:
    parser = _Extractor(page_url)
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: S110  # malformed markup: keep what was parsed
        pass
    return parser.result()


def extract_robots(text: str, robots_url: str) -> list[ExtractedLink]:
    """Paths from Allow/Disallow lines and Sitemap URLs. Wildcard patterns are
    skipped: they describe sets of URLs, not URLs."""
    links: list[ExtractedLink] = []
    for line in text.splitlines()[:5000]:
        key, _, value = line.split("#", 1)[0].partition(":")
        key, value = key.strip().lower(), value.strip()
        if not value or len(links) >= MAX_LINKS_PER_DOCUMENT:
            continue
        if key in ("allow", "disallow") and "*" not in value and "$" not in value:
            links.append(ExtractedLink(join_url(robots_url, value), EndpointSource.ROBOTS))
        elif key == "sitemap":
            links.append(ExtractedLink(join_url(robots_url, value), EndpointSource.SITEMAP))
    return links


_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def extract_sitemap(text: str, sitemap_url: str) -> list[ExtractedLink]:
    """<loc> entries. Parsed with a regex rather than an XML parser, so entity
    expansion and external entities in untrusted XML never come into play."""
    return [
        ExtractedLink(join_url(sitemap_url, match.group(1)), EndpointSource.SITEMAP)
        for match in _LOC.finditer(text)
    ][:MAX_LINKS_PER_DOCUMENT]
