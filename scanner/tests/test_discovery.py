"""End-to-end discovery against a scripted local site."""

import json
from datetime import timedelta
from typing import Any

import pytest

from sentinel_scanner import (
    CancellationToken,
    CrawlOptions,
    DiscoveryConfig,
    DiscoveryResult,
    ScanLimits,
    StopReason,
    run_discovery,
)
from sentinel_scanner.models import EndpointSource, ScanEvent, SkipReason
from tests.conftest import NOW, FakeTime, LabServer, SpyConnector, lab_resolver, make_grant

# Planted by the fixture site; tests assert they never appear in results.
SESSION_SECRET = "S3SSION-SECRET-VALUE"  # noqa: S105  # fake test value
CSRF_SECRET = "CSRF-SECRET-VALUE"  # noqa: S105  # fake test value


def build_site(lab: LabServer) -> None:
    evil = lab.url("/", host="evil.test")
    lab.html(
        "/",
        f"""
        <head><title>Lab Home</title><meta name="generator" content="LabCMS 1.0"></head>
        <a href="/about">About</a>
        <a href="/app/">App</a>
        <a href="/app/item?id=1&token=abc">Item</a>
        <a href="/logout">Log out</a>
        <a href="/account/delete">Delete account</a>
        <a href="/admin/panel">Admin</a>
        <a href="{evil}">Elsewhere</a>
        <a href="//evil.test:{lab.port}/x">Protocol-relative</a>
        <a href="/old">Moved</a>
        <a href="/leave">Leaves scope</a>
        <a href="/deep1">Deep</a>
        <script src="/static/app.js"></script>
        <img src="/img/logo.png">
        <form action="/login" method="post">
          <input type="hidden" name="csrf_token" value="{CSRF_SECRET}">
        </form>
        """,
        headers=[
            ("Server", "nginx/1.25.3"),
            ("X-Powered-By", "PHP/8.2"),
            ("Set-Cookie", f"PHPSESSID={SESSION_SECRET}; Path=/; HttpOnly; SameSite=Lax"),
        ],
    )
    lab.html("/about", '<title>About</title><a href="/contact">Contact</a>')
    lab.html("/contact", "<title>Contact</title>")
    lab.html("/app/", "<title>App</title>")
    lab.redirect("/old", "/about", 301)
    lab.redirect("/leave", lab.url("/landing", host="evil.test"))
    lab.html("/deep1", '<a href="/deep2">2</a>')
    lab.html("/deep2", '<a href="/deep3">3</a>')
    lab.html("/deep3", '<a href="/deep4">4</a>')
    lab.html("/deep4", "")
    lab.route(
        "/robots.txt",
        body=(
            "User-agent: *\nDisallow: /private\nDisallow: /*.php\n"
            f"Sitemap: {lab.url('/sitemap.xml')}\n"
        ),
        content_type="text/plain",
    )
    lab.route(
        "/sitemap.xml",
        body=f"<urlset><url><loc>{lab.url('/from-sitemap')}</loc></url></urlset>",
        content_type="application/xml",
    )
    lab.html("/private", "<title>Private</title>")
    lab.html("/from-sitemap", "<title>From sitemap</title>")
    lab.route(
        "/",
        body=lab.routes["/"].body,
        headers=[*lab.routes["/"].headers, ("Allow", "GET, HEAD, OPTIONS")],
    )


def scan(
    lab: LabServer,
    fake_time: FakeTime,
    *,
    limits: ScanLimits | None = None,
    crawl: CrawlOptions | None = None,
    spy: SpyConnector | None = None,
    **kwargs: Any,
) -> DiscoveryResult:
    config = DiscoveryConfig(
        limits=limits or ScanLimits(max_requests_per_second=20),
        crawl=crawl or CrawlOptions(),
    )
    grant = kwargs.pop("grant", None) or make_grant(lab, scope={"excluded_paths": ("/admin",)})
    return run_discovery(
        grant,
        config,
        resolver=lab_resolver(),
        connector=spy,
        now=fake_time.now,
        monotonic=fake_time.monotonic,
        sleep=fake_time.sleep,
        **kwargs,
    )


@pytest.fixture
def result(lab: LabServer, fake_time: FakeTime) -> DiscoveryResult:
    build_site(lab)
    return scan(lab, fake_time)


def _endpoint(result: DiscoveryResult, path: str, method: str = "GET") -> Any:
    return next(
        e for e in result.endpoints if e.url.split("?")[0].endswith(path) and e.method == method
    )


def test_only_safe_in_scope_pages_are_requested(lab: LabServer, result: DiscoveryResult) -> None:
    requested = {(r.method, r.path) for r in lab.requests}
    assert requested == {
        ("GET", "/"),
        ("OPTIONS", "/"),
        ("GET", "/robots.txt"),
        ("GET", "/sitemap.xml"),
        ("GET", "/about"),
        ("GET", "/contact"),
        ("GET", "/app/"),
        ("GET", "/old"),
        ("GET", "/leave"),
        ("GET", "/deep1"),
        ("GET", "/deep2"),
        ("GET", "/deep3"),
        ("GET", "/private"),
        ("GET", "/from-sitemap"),
    }
    assert lab.hosts_seen == {"lab.test"}
    assert result.stop_reason is StopReason.COMPLETED
    assert result.requests_sent == len(lab.requests)


@pytest.mark.parametrize(
    ("path", "method", "reason"),
    [
        ("/app/item", "GET", SkipReason.QUERY_STRING),
        ("/logout", "GET", SkipReason.RISKY_PATH),
        ("/account/delete", "GET", SkipReason.RISKY_PATH),
        ("/admin/panel", "GET", SkipReason.OUT_OF_SCOPE),  # excluded path
        ("/login", "POST", SkipReason.FORM_NOT_SUBMITTED),
        ("/static/app.js", "GET", SkipReason.STATIC_ASSET),
        ("/img/logo.png", "GET", SkipReason.STATIC_ASSET),
        ("/deep4", "GET", SkipReason.DEPTH_LIMIT),
    ],
)
def test_skipped_endpoints_are_recorded_with_reason(
    result: DiscoveryResult, path: str, method: str, reason: SkipReason
) -> None:
    endpoint = _endpoint(result, path, method)
    assert not endpoint.fetched
    assert endpoint.skip_reason is reason


def test_out_of_scope_links_and_redirects(result: DiscoveryResult) -> None:
    external = [e for e in result.endpoints if "evil.test" in e.url]
    assert external and all(not e.fetched for e in external)
    assert all(e.skip_reason is SkipReason.OUT_OF_SCOPE for e in external)
    assert any(e.source is EndpointSource.REDIRECT for e in external)
    blocked = [e for e in result.events if e.code == "host_out_of_scope"]
    assert blocked and blocked[0].level == "blocked"


def test_endpoint_details(result: DiscoveryResult) -> None:
    item = _endpoint(result, "/app/item")
    assert item.query_param_names == ["id", "token"]
    assert "abc" not in item.url  # sensitive query value redacted
    assert _endpoint(result, "/private").source is EndpointSource.ROBOTS
    assert _endpoint(result, "/from-sitemap").source is EndpointSource.SITEMAP
    assert _endpoint(result, "/about").fetched


def test_page_observations(result: DiscoveryResult) -> None:
    home = next(
        p for p in result.pages if p.url.endswith("/") and p.method == "GET" and p.depth == 0
    )
    assert home.status == 200
    assert home.title == "Lab Home"
    assert home.content_type == "text/html; charset=utf-8"
    [cookie] = home.cookies
    assert (cookie.name, cookie.http_only, cookie.secure, cookie.same_site) == (
        "PHPSESSID",
        True,
        False,
        "Lax",
    )
    assert {(h.source, h.value) for h in home.hints} >= {
        ("header:server", "nginx/1.25.3"),
        ("header:x-powered-by", "PHP/8.2"),
        ("meta:generator", "LabCMS 1.0"),
        ("cookie:PHPSESSID", "PHP"),
    }
    options = next(p for p in result.pages if p.method == "OPTIONS")
    assert options.allowed_methods == ["GET", "HEAD", "OPTIONS"]
    moved = next(p for p in result.pages if p.url.endswith("/old"))
    assert moved.status == 301 and moved.redirect_location == "/about"


def test_every_page_has_evidence(result: DiscoveryResult) -> None:
    by_id = {e.id: e for e in result.evidence}
    assert len(by_id) == len(result.pages)
    for page in result.pages:
        evidence = by_id[page.evidence_id]
        assert evidence.status == page.status
        assert evidence.peer == "127.0.0.1"
        assert len(evidence.body_sha256) == 64


def test_secrets_never_leave_the_scanner(result: DiscoveryResult) -> None:
    serialized = json.dumps(result.to_dict())
    assert SESSION_SECRET not in serialized
    assert CSRF_SECRET not in serialized
    home_evidence = next(e for e in result.evidence if e.url.endswith("/") and e.method == "GET")
    assert "response_header:Set-Cookie" in home_evidence.redactions
    assert "body:hidden_input_value" in home_evidence.redactions


def test_result_is_json_serializable(result: DiscoveryResult) -> None:
    data = json.loads(json.dumps(result.to_dict()))
    assert data["schema_version"] == 1
    assert data["stop_reason"] == "completed"
    assert data["started_at"] == NOW.isoformat()
    assert {"pages", "endpoints", "events", "evidence"} <= set(data)


def test_crawl_options_can_disable_robots_and_sitemap(lab: LabServer, fake_time: FakeTime) -> None:
    build_site(lab)
    scan(lab, fake_time, crawl=CrawlOptions(fetch_robots=False, fetch_sitemap=False))
    assert "/robots.txt" not in lab.paths()
    assert "/sitemap.xml" not in lab.paths()


def test_query_links_can_be_followed_when_enabled(lab: LabServer, fake_time: FakeTime) -> None:
    build_site(lab)
    scan(lab, fake_time, crawl=CrawlOptions(follow_query_links=True))
    assert "/app/item?id=1&token=abc" in lab.paths()
    assert "/logout" not in lab.paths()  # risky paths stay unvisited


# --- Stop reasons --------------------------------------------------------------------------


def test_request_limit_stops_the_scan(lab: LabServer, fake_time: FakeTime) -> None:
    build_site(lab)
    result = scan(lab, fake_time, limits=ScanLimits(max_requests=3, max_requests_per_second=20))
    assert result.stop_reason is StopReason.REQUEST_LIMIT
    assert len(lab.requests) == 3 == result.requests_sent
    assert any(e.skip_reason is SkipReason.NOT_REACHED for e in result.endpoints)


def test_page_limit_stops_the_scan(lab: LabServer, fake_time: FakeTime) -> None:
    build_site(lab)
    result = scan(lab, fake_time, limits=ScanLimits(max_pages=3, max_requests_per_second=20))
    assert result.stop_reason is StopReason.PAGE_LIMIT
    assert len(result.pages) <= 4  # a fetch in progress may add its redirect hop


def test_time_budget_stops_the_scan(lab: LabServer, fake_time: FakeTime) -> None:
    build_site(lab)
    # 2 requests/s -> each request after the first waits 0.5s of (fake) time.
    result = scan(
        lab, fake_time, limits=ScanLimits(max_scan_seconds=1.2, max_requests_per_second=2)
    )
    assert result.stop_reason is StopReason.TIME_BUDGET
    assert len(lab.requests) == 3


def test_authorization_expiry_stops_the_scan(lab: LabServer, fake_time: FakeTime) -> None:
    build_site(lab)
    grant = make_grant(lab, valid_until=NOW + timedelta(seconds=1))
    result = scan(lab, fake_time, limits=ScanLimits(max_requests_per_second=2), grant=grant)
    assert result.stop_reason is StopReason.AUTHORIZATION_EXPIRED
    assert len(lab.requests) == 2  # at t=0 and t=0.5; the next slot is at t=1.0
    assert any(e.code == "authorization_expired" for e in result.events)


def test_cancellation_stops_the_scan(lab: LabServer, fake_time: FakeTime) -> None:
    build_site(lab)
    token = CancellationToken()
    seen: list[ScanEvent] = []

    def on_event(event: ScanEvent) -> None:
        seen.append(event)
        if event.code == "scan_started":
            token.cancel()

    result = scan(lab, fake_time, cancel=token, on_event=on_event)
    assert result.stop_reason is StopReason.CANCELLED
    assert lab.requests == []
    assert [e.code for e in seen] == [e.code for e in result.events]
