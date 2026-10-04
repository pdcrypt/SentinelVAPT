import copy
import re

import pytest

from sentinel_reports import HtmlPolicyViolation, render_report
from sentinel_reports.html import check_html_policy, link_allowed
from tests.factory import snapshot, with_text_everywhere

PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
    "javascript:alert(1)",
    "{{ 7*7 }}{% raw %}x{% endraw %}{# c #}",
    "</style><script>alert(1)</script>",
    "<a href='https://evil.example'>click</a>",
    "\u202eevil\u202c and \u0000 null",
    "<meta http-equiv=refresh content='0;url=https://evil.example'>",
    "url(https://evil.example/x.png) @import 'https://evil.example'",
]


def html_of(s: dict[str, object]) -> str:
    (artifact,) = render_report(s, ["html"])
    return artifact.content.decode("utf-8")


def test_html_renders_every_section() -> None:
    html = html_of(snapshot())
    for section in (
        "executive-summary", "engagement", "scope", "methodology", "scan-summary",
        "findings-summary", "findings", "false-positives", "evidence", "timeline",
        "limitations", "integrity",
    ):  # fmt: skip
        assert f'id="{section}"' in html
    assert "SV-R-000001" in html
    assert "Lab target" in html
    assert "SHA-256 of the unredacted captured response bytes." in html
    assert "LAB-1" in html  # authorization reference


@pytest.mark.parametrize("payload", PAYLOADS)
def test_user_and_target_data_is_escaped_everywhere(payload: str) -> None:
    html = html_of(with_text_everywhere(payload))
    check_html_policy(html)  # also enforced inside render_report
    if any(c in payload for c in "<>\"'"):
        assert payload not in html  # never emitted unescaped
    assert "<script" not in html
    assert not re.search(r"<(img|svg onload|meta http-equiv=refresh|a href='https)", html)
    assert 'href="https://evil.example' not in html
    assert "\u0000" not in html
    assert "\u202e" not in html


def test_template_syntax_in_data_is_shown_literally_not_evaluated() -> None:
    html = html_of(with_text_everywhere("{{ 7*7 }} {{ config }}"))
    assert "{{ 7*7 }}" in html
    assert ">49<" not in html


def test_only_allowlisted_reference_links_are_clickable() -> None:
    s = snapshot()
    s["issues"][0]["rule"]["references"] = [
        "https://cwe.mitre.org/data/definitions/319.html",
        "https://evil.example/cwe",
    ]
    html = html_of(s)
    assert '<a href="https://cwe.mitre.org/data/definitions/319.html">' in html
    assert "https://evil.example/cwe" in html  # shown as text
    assert 'href="https://evil.example' not in html


def test_target_urls_are_text_not_links() -> None:
    html = html_of(snapshot())
    assert 'href="http://lab.test' not in html
    assert "http://lab.test:8080/page001" in html


@pytest.mark.parametrize(
    "url",
    ["https://cwe.mitre.org/x", "https://wstg.owasp.org/v4.2/", "https://top10.owasp.org/2025/"],
)
def test_link_allowlist_accepts(url: str) -> None:
    assert link_allowed(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://cwe.mitre.org/x",
        "https://cwe.mitre.org.evil.example/x",
        "https://user@cwe.mitre.org/x",
        "javascript:alert(1)",
        "https://evil.example/",
        "//cwe.mitre.org/x",
        None,
    ],
)
def test_link_allowlist_rejects(url: object) -> None:
    assert not link_allowed(url)


@pytest.mark.parametrize(
    "fragment",
    [
        "<script>x</script>",
        '<div onclick="x"></div>',
        '<div style="background:url(x)"></div>',
        '<a href="https://evil.example/">x</a>',
        '<a href="javascript:alert(1)">x</a>',
        '<iframe src="x"></iframe>',
        '<img src="x">',
        '<link rel="stylesheet" href="x">',
        '<meta http-equiv="refresh" content="0">',
        '<meta name="referrer" content="x">',
        "<style>body{background:url(https://x)}</style>",
        "<style>@import 'x';</style>",
        '<form action="x"></form>',
        '<svg><use href="x"></use></svg>',
        '<base href="https://evil.example/">',
        '<object data="x"></object>',
    ],
)
def test_policy_checker_rejects(fragment: str) -> None:
    with pytest.raises(HtmlPolicyViolation):
        check_html_policy(f"<html><body>{fragment}</body></html>")


def test_report_markup_is_never_double_escaped() -> None:
    # The factory's data contains no markup characters, so any escaped tag in
    # the output would be the template's own markup escaped a second time.
    html = html_of(snapshot())
    assert "&lt;" not in html and "&gt;" not in html
    findings = html.split('id="findings"')[1].split('id="false-positives"')[0]
    assert "<table>" in findings and "<td" in findings


def test_policy_checker_accepts_the_report() -> None:
    check_html_policy(html_of(snapshot()))


def test_draft_and_final_presentation() -> None:
    draft = html_of(snapshot())
    assert 'class="watermark"' in draft and "This is a draft" in draft
    s = snapshot()
    s["document"]["kind"] = "final"
    s["engagement"]["assessment"].update(
        status="completed", completed_at="2026-10-04T12:20:00+00:00"
    )
    final = html_of(s)
    assert 'class="watermark"' not in final and "This is a draft" not in final


def test_open_findings_are_marked_as_requiring_verification() -> None:
    s = snapshot()
    s["issues"][0]["instances"][0]["detection_type"] = "manual_verification_required"
    html = html_of(s)
    assert "Requires verification" in html
    assert "still" in html and "manual verification" in html


def test_false_positives_are_listed_separately_with_their_reason() -> None:
    html = html_of(snapshot())
    fp_section = html.split('id="false-positives"')[1].split('id="evidence"')[0]
    assert "Lab banner" in fp_section
    findings_section = html.split('id="findings"')[1].split('id="false-positives"')[0]
    assert "Lab banner" not in findings_section


def test_no_findings_is_not_presented_as_secure() -> None:
    s = snapshot(issues=[], evidence=[])
    html = html_of(s)
    assert "does not mean the" in html and "secure" in html


def test_coverage_notes_are_explained() -> None:
    s = snapshot()
    s["scan"]["coverage_notes"] = ["partial_scan", "tls_trust_not_evaluated", "unknown_note"]
    html = html_of(s)
    assert "stopped before completing its crawl" in html
    assert "certificate trust was not evaluated" in html
    assert "unknown_note" in html


def test_html_is_deterministic() -> None:
    s = snapshot()
    assert html_of(s) == html_of(copy.deepcopy(s))


def test_html_contains_csp_and_no_scripts_or_external_resources() -> None:
    html = html_of(snapshot())
    assert '<meta http-equiv="Content-Security-Policy"' in html
    assert "default-src &#39;none&#39;" in html or "default-src 'none'" in html
    assert "<script" not in html
    assert not re.search(r'\ssrc="', html)
