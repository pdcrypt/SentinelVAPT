"""Link extraction, cookie parsing and technology hints."""

from sentinel_scanner.discovery.cookies import parse_set_cookie
from sentinel_scanner.discovery.hints import collect_hints
from sentinel_scanner.discovery.links import (
    MAX_LINKS_PER_DOCUMENT,
    extract_html,
    extract_robots,
    extract_sitemap,
)
from sentinel_scanner.models import EndpointSource

PAGE = "http://lab.test/dir/page"


def test_html_links_are_extracted_and_resolved() -> None:
    doc = extract_html(
        """
        <title>  Lab   Home </title>
        <meta name="generator" content="WordPress 6.5">
        <a href="/about">About</a>
        <a href="next">Relative</a>
        <a href="#top">Fragment only</a>
        <a href="/x#section">With fragment</a>
        <a href="javascript:alert(1)">JS</a>
        <a href="mailto:a@b.test">Mail</a>
        <link rel="stylesheet" href="/css/site.css">
        <script src="/js/app.js"></script>
        <img src="/img/logo.png">
        <iframe src="/frame"></iframe>
        <form action="/login" method="post"></form>
        <form></form>
        """,
        PAGE,
    )
    found = {(link.url, link.source, link.method) for link in doc.links}
    assert found == {
        ("http://lab.test/about", EndpointSource.LINK, "GET"),
        ("http://lab.test/dir/next", EndpointSource.LINK, "GET"),
        ("http://lab.test/x", EndpointSource.LINK, "GET"),
        ("http://lab.test/css/site.css", EndpointSource.STYLESHEET, "GET"),
        ("http://lab.test/js/app.js", EndpointSource.SCRIPT, "GET"),
        ("http://lab.test/img/logo.png", EndpointSource.IMAGE, "GET"),
        ("http://lab.test/frame", EndpointSource.FRAME, "GET"),
        ("http://lab.test/login", EndpointSource.FORM, "POST"),
        (PAGE, EndpointSource.FORM, "GET"),
    }
    assert doc.title == "Lab Home"
    assert doc.generator == "WordPress 6.5"


def test_base_href_changes_resolution_once() -> None:
    doc = extract_html('<base href="/root/"><base href="/ignored/"><a href="child">c</a>', PAGE)
    assert [link.url for link in doc.links] == ["http://lab.test/root/child"]


def test_link_count_is_capped() -> None:
    html = "".join(f'<a href="/p{i}">x</a>' for i in range(MAX_LINKS_PER_DOCUMENT + 50))
    assert len(extract_html(html, PAGE).links) == MAX_LINKS_PER_DOCUMENT


def test_malformed_html_does_not_raise() -> None:
    doc = extract_html('<a href="/ok">x</a><<<>>><a href="/also"', PAGE)
    assert "http://lab.test/ok" in [link.url for link in doc.links]


def test_robots_parsing() -> None:
    links = extract_robots(
        "User-agent: *\nDisallow: /private\nAllow: /public # note\nDisallow: /*.php\n"
        "Disallow: /end$\nDisallow:\nSitemap: http://lab.test/map.xml\n",
        "http://lab.test/robots.txt",
    )
    assert [(link.url, link.source) for link in links] == [
        ("http://lab.test/private", EndpointSource.ROBOTS),
        ("http://lab.test/public", EndpointSource.ROBOTS),
        ("http://lab.test/map.xml", EndpointSource.SITEMAP),
    ]


def test_sitemap_parsing_ignores_entities() -> None:
    xml = (
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
        "<urlset><url><loc> http://lab.test/one </loc></url><url><loc>/two</loc></url>"
        "<url><loc>&b;</loc></url></urlset>"
    )
    links = extract_sitemap(xml, "http://lab.test/sitemap.xml")
    assert [link.url for link in links] == [
        "http://lab.test/one",
        "http://lab.test/two",
        "http://lab.test/&b;",  # recorded literally; entities are never expanded
    ]


def test_cookie_flags_without_values() -> None:
    cookie = parse_set_cookie(
        "SESSION=topsecret; Domain=lab.test; Path=/app; Secure; HttpOnly; SameSite=Strict; "
        "Max-Age=3600"
    )
    assert cookie is not None
    assert (cookie.name, cookie.secure, cookie.http_only, cookie.same_site) == (
        "SESSION",
        True,
        True,
        "Strict",
    )
    assert (cookie.domain, cookie.path, cookie.has_expiry) == ("lab.test", "/app", True)
    assert "topsecret" not in repr(cookie)

    plain = parse_set_cookie("pref=dark")
    assert plain is not None
    assert (plain.secure, plain.http_only, plain.same_site, plain.has_expiry) == (
        False,
        False,
        None,
        False,
    )
    assert parse_set_cookie("garbage") is None


def test_technology_hints() -> None:
    cookies = [c for c in [parse_set_cookie("PHPSESSID=1"), parse_set_cookie("x=1")] if c]
    hints = collect_hints(
        [("Server", "nginx/1.25.3"), ("X-Powered-By", "PHP/8.2"), ("Content-Type", "text/html")],
        cookies,
        "WordPress 6.5",
    )
    assert {(h.source, h.value) for h in hints} == {
        ("header:server", "nginx/1.25.3"),
        ("header:x-powered-by", "PHP/8.2"),
        ("meta:generator", "WordPress 6.5"),
        ("cookie:PHPSESSID", "PHP"),
    }
