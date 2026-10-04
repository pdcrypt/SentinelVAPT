from dataclasses import replace

from sentinel_analysis.context import MAX_HEADERS_PER_RESPONSE, RuleContext
from sentinel_analysis.observations import CookieObs

from tests.builders import Page, build, cookie


def test_indexes_and_lookups() -> None:
    home = Page(
        "http://Lab.Test/", headers=[("X-Test", "a"), ("x-test", "b")], cookies=[cookie("sid")]
    )
    other = Page("https://lab.test:8443/x")
    ctx = RuleContext(build([other, home]))
    assert ctx.origins == ("http://lab.test:80", "https://lab.test:8443")
    [response] = ctx.responses_at("http://lab.test:80")
    assert ctx.header(response, "X-TEST") == "a"
    assert ctx.header_values(response, "x-test") == ("a", "b")
    assert ctx.is_html(response) and ctx.is_success(response)
    [site] = ctx.cookie_sites
    assert (site.origin, site.scheme, site.cookie.name) == ("http://lab.test:80", "http", "sid")
    assert ctx.evidence_ids == {home.evidence_id, other.evidence_id}


def test_cookies_for_unknown_endpoints_are_ignored() -> None:
    obs = build([Page("http://lab.test/")])
    stray = CookieObs(
        endpoint_id="unknown", name="sid", secure=False, http_only=False, same_site=None
    )
    ctx = RuleContext(replace(obs, cookies=(stray,)))
    assert ctx.cookie_sites == ()


def test_values_are_bounded() -> None:
    noisy = Page(
        "http://lab.test/",
        headers=[(f"H{i}", "v" * 10_000) for i in range(1000)],
        body="b" * 100_000,
    )
    ctx = RuleContext(build([noisy]))
    [response] = ctx.responses
    assert len(response.headers) == MAX_HEADERS_PER_RESPONSE
    assert max(len(v) for _, v in response.headers) <= 4096
    assert len(response.body_excerpt) <= 8192


def test_order_is_deterministic() -> None:
    pages = [Page(f"http://lab.test/{c}") for c in "dcba"]
    ctx1 = RuleContext(build(pages))
    ctx2 = RuleContext(replace(build(pages), responses=tuple(reversed(build(pages).responses))))
    assert [r.url for r in ctx1.responses] == sorted(r.url for r in ctx1.responses)
    assert [r.url for r in ctx2.responses] == [r.url for r in ctx1.responses]


def test_truncation_keeps_the_same_rows_regardless_of_input_order() -> None:
    from sentinel_analysis import analyze
    from sentinel_analysis.context import MAX_EVENTS
    from sentinel_analysis.engine import COVERAGE_TRUNCATED
    from sentinel_analysis.observations import EventObs

    base = build([Page("http://127.0.0.1:8080/")])
    events = tuple(EventObs("warning", f"code_{i:05d}", "m", None) for i in range(MAX_EVENTS + 10))
    forward = replace(base, events=events)
    backward = replace(base, events=events[::-1])
    assert RuleContext(forward).events == RuleContext(backward).events
    assert RuleContext(forward).truncated
    assert COVERAGE_TRUNCATED in analyze(forward).coverage_notes
    assert COVERAGE_TRUNCATED not in analyze(base).coverage_notes
