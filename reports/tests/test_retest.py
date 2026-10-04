"""Retest reports (sentinelvapt.retest-report/1): schema, consistency,
derived figures, rendering of every comparison state, determinism, security."""

import copy
import json
import re
import shutil
import socket
from pathlib import Path
from typing import Any

import pytest

from sentinel_reports import ArtifactTooLarge, SnapshotInvalid, TemplateMismatch, canonical_json
from sentinel_reports.html import check_html_policy
from sentinel_reports.retest import (
    RETEST_TEMPLATES,
    STATES,
    derive_retest,
    render_retest_report,
    retest_content_digest,
    retest_snapshot_digest,
    validate_retest_snapshot,
)
from sentinel_reports.retest import render as retest_render
from sentinel_reports.retest.render import retest_locked_hashes, verified_retest_hash
from sentinel_reports.templates import TEMPLATES, compute_hash, locked_hashes
from tests.retest_factory import (
    evidence,
    finalize,
    prune_evidence,
    record,
    snapshot,
    uid,
    view,
    with_text_everywhere,
)

LOCAL = ["json", "html"]


def html_of(s: dict[str, Any]) -> str:
    (artifact,) = render_retest_report(s, ["html"])
    return artifact.content.decode("utf-8")


def section(html: str, state: str) -> str:
    start = html.index(f'id="state-{state}"')
    end = html.index("</section>", start)
    return html[start:end]


# --- schema and consistency ------------------------------------------------------------


def test_factory_snapshot_is_valid() -> None:
    validate_retest_snapshot(snapshot())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.update(extra=1),
        lambda s: s["document"].update(number="SV-R-000001"),
        lambda s: s["document"]["template"].update(id="sv-standard"),
        lambda s: s["records"][0].update(state="resolved"),
        lambda s: s["records"][0].update(raw="x"),
        lambda s: s["evidence"][0].update(request_headers=[]),
        lambda s: s["evidence"][0].update(excerpt="x" * 1025),
        lambda s: s["records"][2]["baseline"].update(evidence_ids=[uid(1)] * 26),
        lambda s: s["records"][4].update(coverage_evidence_ids=[uid(i) for i in range(26)]),
        lambda s: s.update(limitations=["everything_is_fine"]),
        lambda s: s["authorization"]["retest"]["scope"].update(notes="secret"),
        lambda s: s["comparison"].update(policy_version="cmp-x"),
    ],
)
def test_schema_rejects_malformed_snapshots(mutate: Any) -> None:
    s = snapshot()
    mutate(s)
    with pytest.raises(SnapshotInvalid):
        validate_retest_snapshot(s)


def test_more_than_5000_evidence_entries_are_rejected() -> None:
    s = snapshot()
    extra = [evidence("current", 100 + i) for i in range(5000)]
    s["records"][0]["current"]["evidence_ids"] = []
    s["evidence"].extend(extra)
    with pytest.raises(SnapshotInvalid):
        validate_retest_snapshot(finalize(s))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda s: s["records"].reverse(), "records"),
        (lambda s: s["evidence"].reverse(), "evidence"),
        (lambda s: s["comparison"]["summary"].update(fixed=9), "summary"),
        (lambda s: s["comparison"].update(records_sha256="1" * 64), "records digest"),
        (lambda s: s["evidence"][0].update(url="http://changed/"), "entry digest"),
        (lambda s: s["evidence"][0].update(scan_id=uid(999)), "wrong scan"),
    ],
)
def test_integrity_checks(mutate: Any, message: str) -> None:
    s = snapshot()
    mutate(s)
    with pytest.raises(SnapshotInvalid, match=message):
        validate_retest_snapshot(s)


def _record(s: dict[str, Any], state: str) -> dict[str, Any]:
    return next(r for r in s["records"] if r["state"] == state)


def _cov(s: dict[str, Any]) -> str:
    return str(_record(s, "fixed")["coverage_evidence_ids"][0])


def _cur(s: dict[str, Any], state: str) -> Any:
    return _record(s, state)["current"]


def _base_ev(s: dict[str, Any]) -> str:
    return str(_record(s, "fixed")["baseline"]["evidence_ids"][0])


def _history() -> dict[str, Any]:
    return {
        "comparison_id": uid(1),
        "assessment_id": uid(2),
        "assessment_name": "x",
        "state": "fixed",
    }


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda s: _record(s, "fixed").update(coverage_evidence_ids=[]), "coverage evidence"),
        (
            lambda s: _record(s, "fixed")["triage_when_compared"].update(baseline="false_positive"),
            "false positive is never fixed",
        ),
        (
            lambda s: _record(s, "dismissed")["triage_when_compared"].update(baseline="open"),
            "dismissed requires",
        ),
        (lambda s: _record(s, "unchanged").update(coverage_evidence_ids=[_cov(s)]), "not fixed"),
        (lambda s: _record(s, "reopened").update(history=None), "reopened requires"),
        (lambda s: _record(s, "new").update(state="unchanged"), "both findings"),
        (lambda s: _record(s, "fixed").update(current=_cur(s, "new")), "only a baseline"),
        (lambda s: _record(s, "new")["triage_when_reported"].update(baseline="open"), "triage"),
        (lambda s: _record(s, "unchanged").update(history=_history()), "history"),
        (lambda s: s["rules"].clear(), "rule metadata"),
        (lambda s: s["lineage"].pop(), "lineage"),
        # Baseline evidence presented as retest coverage (wrong role).
        (lambda s: _record(s, "fixed").update(coverage_evidence_ids=[_base_ev(s)]), "references"),
        (lambda s: s["evidence"].pop(), "references"),
    ],
)
def test_consistency_checks(mutate: Any, message: str) -> None:
    s = snapshot()
    mutate(s)
    with pytest.raises(SnapshotInvalid, match=message):
        validate_retest_snapshot(finalize(s))


def test_records_and_evidence_must_be_in_canonical_order() -> None:
    from sentinel_reports.retest.snapshot import records_sha256

    s = snapshot()
    s["records"].reverse()  # digest and counts stay consistent with the order
    s["comparison"]["records_sha256"] = records_sha256(s["records"])
    with pytest.raises(SnapshotInvalid, match="records not in canonical order"):
        validate_retest_snapshot(s)
    s = snapshot()
    s["evidence"].reverse()
    with pytest.raises(SnapshotInvalid, match="evidence not in canonical order"):
        validate_retest_snapshot(s)


def test_digests_exclude_only_identity_and_time() -> None:
    a, b = snapshot(), snapshot()
    b["document"].update(
        report_id=uid(77), number="SV-RT-000077", created_at="2027-01-01T00:00:00+00:00"
    )
    assert retest_snapshot_digest(a) != retest_snapshot_digest(b)
    assert retest_content_digest(a) == retest_content_digest(b)
    c = copy.deepcopy(a)
    _record(c, "new")["triage_when_reported"]["current"] = "confirmed"
    assert retest_content_digest(a) != retest_content_digest(c)


# --- derived figures ---------------------------------------------------------------------


def test_counts_and_sections_cover_every_state() -> None:
    d = derive_retest(snapshot())
    assert d["total_records"] == 8
    assert d["counts"] == {s: 1 for s in d["counts"]}
    assert [s["state"] for s in d["sections"]] == [
        "new",
        "reopened",
        "still_open",
        "unchanged",
        "fixed",
        "dismissed",
        "not_retested",
        "not_comparable",
    ]


def test_metrics_formulas() -> None:
    d = derive_retest(snapshot())
    # baseline_active: still_open, unchanged, fixed, not_retested, not_comparable
    # (dismissed is a baseline false positive; new and reopened have no baseline).
    assert d["baseline_active"] == 5
    assert d["metrics"]["verified_fixed_share"] == {
        "numerator": 1,
        "denominator": 5,
        "value": "20.0%",
    }
    assert d["metrics"]["unverified_share"] == {"numerator": 2, "denominator": 5, "value": "40.0%"}


def test_metrics_are_na_without_active_baseline_findings() -> None:
    s = snapshot()
    s["records"] = [r for r in s["records"] if r["state"] in ("new", "reopened", "dismissed")]
    prune_evidence(s)
    s = finalize(s)
    validate_retest_snapshot(s)
    d = derive_retest(s)
    assert d["baseline_active"] == 0
    assert d["metrics"]["verified_fixed_share"]["value"] == "n/a"
    assert d["metrics"]["unverified_share"]["value"] == "n/a"


@pytest.mark.parametrize(
    ("num", "den", "text"),
    [(1, 3, "33.3%"), (2, 3, "66.7%"), (1, 8, "12.5%"), (0, 4, "0.0%"), (4, 4, "100.0%")],
)
def test_percent_rounding_is_exact(num: int, den: int, text: str) -> None:
    from sentinel_reports.retest.derive import _percent

    assert _percent(num, den) == text


def test_still_open_differences_ignore_counters() -> None:
    d = derive_retest(snapshot())
    (changes,) = d["differences"].values()
    assert changes == [
        {"attribute": "severity", "baseline": "low", "current": "informational"},
        {"attribute": "details.value", "baseline": "nginx/1.25", "current": "nginx/1.27"},
    ]


def test_records_are_ordered_by_severity_rule_and_subject() -> None:
    s = snapshot()
    extra = record(
        20,
        "new",
        cur=view(20, [], severity="high", subject_key="http://z.test:80"),
        reasons=["first_observed"],
    )
    s["records"].append(extra)
    s = finalize(s)
    new_section = derive_retest(s)["sections"][0]["records"]
    assert [r["fingerprint"][-2:] for r in new_section] == ["14", "01"]  # high before low


# --- rendering -----------------------------------------------------------------------------


def test_every_section_renders_in_order() -> None:
    html = html_of(snapshot())
    ids = [
        "executive-summary",
        "scope",
        "overview",
        "remediation-summary",
        "state-new",
        "state-reopened",
        "state-still_open",
        "state-unchanged",
        "state-fixed",
        "state-dismissed",
        "state-not_retested",
        "state-not_comparable",
        "evidence",
        "rule-versions",
        "limitations",
        "lineage",
        "methodology",
    ]
    positions = [html.index(f'id="{i}"') for i in ids]
    assert positions == sorted(positions)
    for n, title in [
        (5, "New findings"),
        (12, "Not comparable"),
        (13, "Evidence"),
        (17, "Methodology"),
    ]:
        assert f"{n}. {title}" in html


def test_empty_state_sections_say_none() -> None:
    s = snapshot()
    s["records"] = [r for r in s["records"] if r["state"] == "unchanged"]
    prune_evidence(s)
    s = finalize(s)
    html = html_of(s)
    for state in (
        "new",
        "reopened",
        "still_open",
        "fixed",
        "dismissed",
        "not_retested",
        "not_comparable",
    ):
        assert "<p>None.</p>" in section(html, state), state
    assert "<p>None.</p>" not in section(html, "unchanged")


def test_fixed_shows_its_coverage_evidence() -> None:
    html = html_of(snapshot())
    fixed = section(html, "fixed")
    assert "Retest evidence showing the subject was examined" in fixed
    for evidence_id in _record(snapshot(), "fixed")["coverage_evidence_ids"]:
        assert f'href="#ev-current-{evidence_id}"' in fixed
        assert f'id="ev-current-{evidence_id}"' in html


def test_dismissed_and_safety_states_are_never_remediation() -> None:
    html = html_of(snapshot())
    assert "Dismissed is not fixed" in section(html, "dismissed")
    assert _record(snapshot(), "dismissed")["fingerprint"] not in section(html, "fixed")
    for state in ("not_retested", "not_comparable"):
        text = section(html, state)
        assert "NOT evidence of remediation" in text
        assert "Unverified, not a remediation result" in text
    assert "could not be retested" in html  # executive summary callout


def test_reopened_cites_the_previous_comparison_and_still_open_shows_changes() -> None:
    html = html_of(snapshot())
    reopened = section(html, "reopened")
    assert uid(901) in reopened and "Retest B" in reopened
    still_open = section(html, "still_open")
    assert "What changed" in still_open
    assert "nginx/1.25" in still_open and "nginx/1.27" in still_open


STATE_CELL = re.compile(
    r'<th scope="row">Comparison state</th><td><strong class="mono">([^<]*)</strong>'
)


def test_triage_is_labelled_separately_from_comparison_state() -> None:
    s = snapshot()
    html = html_of(s)
    # Every record shows its persisted comparison state, never a triage label.
    for state in STATES:
        cells = STATE_CELL.findall(section(html, state))
        expected = sum(1 for r in s["records"] if r["state"] == state)
        assert cells == [state.upper()] * expected
    assert len(STATE_CELL.findall(html)) == len(s["records"])
    assert html.count("Triage status (when compared)") == len(s["records"])
    assert html.count("Triage status (when reported)") == len(s["records"])
    dismissed = section(html, "dismissed")
    assert '<strong class="mono">DISMISSED</strong>' in dismissed  # the comparison state
    assert "baseline: False positive" in dismissed  # the triage status, labelled as such


def test_triage_never_replaces_the_comparison_state() -> None:
    """Triage changed after the comparison: both triage values are shown,
    labelled, and the comparison state is still the persisted one."""
    s = snapshot()
    fixed = _record(s, "fixed")
    fixed["triage_when_reported"]["baseline"] = "confirmed"
    html = html_of(finalize(s))
    text = section(html, "fixed")
    assert STATE_CELL.findall(text) == ["FIXED"]
    assert "baseline: Confirmed" in text


def test_scope_narrowing_is_disclosed() -> None:
    html = html_of(snapshot())
    scope = html[html.index('id="scope"') : html.index('id="overview"')]
    assert "narrower than the baseline scope" in scope
    assert "Paths newly excluded: /error" in scope
    assert "That is not remediation" in scope
    s = snapshot()
    s["scope_change"]["narrower"] = False
    s["scope_change"]["exclusions_added"] = []
    assert "same as the baseline scope" in html_of(s)


def test_rule_version_differences_and_unknown_versions() -> None:
    s = snapshot()
    s["engagement"]["retest"]["run"]["rule_versions"] = [{"rule_id": "SV-HDR-002", "version": 2}]
    text = html_of(s)
    rv = text[text.index('id="rule-versions"') : text.index('id="limitations"')]
    assert "SV-HDR-002" in rv and ">1<" in rv and ">2<" in rv
    assert _record(s, "not_comparable")["fingerprint"] in rv  # affected record listed
    s["engagement"]["baseline"]["run"]["rule_versions"] = None
    text = html_of(s)
    assert "were not recorded" in text


def test_metrics_render_with_formula_and_label() -> None:
    html = html_of(snapshot())
    summary = html[html.index('id="remediation-summary"') : html.index('id="state-new"')]
    assert "SentinelVAPT-specific measures, not industry metrics" in summary
    assert "fixed / baseline_active = 1 / 5" in summary and "20.0%" in summary
    assert "baseline_active = 2 / 5" in summary and "40.0%" in summary


def test_lineage_and_draft_watermark() -> None:
    html = html_of(snapshot())
    lineage = html[html.index('id="lineage"') : html.index('id="methodology"')]
    assert "Baseline A" in lineage and "Retest B" in lineage and "Retest C" in lineage
    assert 'class="watermark"' not in html
    s = snapshot()
    s["document"]["kind"] = "draft"
    assert 'class="watermark"' in html_of(s)


# --- determinism and artifacts --------------------------------------------------------------


def test_rendering_is_deterministic_and_json_is_canonical() -> None:
    first = render_retest_report(snapshot(), LOCAL)
    second = render_retest_report(snapshot(), LOCAL)
    assert [a.content for a in first] == [a.content for a in second]
    document = json.loads(first[0].content)
    assert first[0].content == canonical_json(document)
    assert document["schema_version"] == "sentinelvapt.retest-report-document/1"
    assert document["snapshot_schema_version"] == "sentinelvapt.retest-report/1"
    assert document["integrity"]["records_sha256"] == snapshot()["comparison"]["records_sha256"]


def test_size_limit_and_formats() -> None:
    with pytest.raises(ArtifactTooLarge):
        render_retest_report(snapshot(), ["html"], max_artifact_bytes=1000)
    with pytest.raises(SnapshotInvalid):
        render_retest_report(snapshot(), ["docx"])


def test_rendering_needs_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_: Any, **__: Any) -> Any:
        raise AssertionError("network access attempted")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, refuse)
    assert [a.format for a in render_retest_report(snapshot(), LOCAL)] == LOCAL


# --- security ---------------------------------------------------------------------------------

PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "{{ 7*7 }}{% raw %}x{% endraw %}",
    "</style><script>x</script>",
    "<a href='https://evil.example'>x</a>",
    "javascript:alert(1)",
    "‮evil‬ and \u0000 null",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_injection_is_escaped(payload: str) -> None:
    html = html_of(with_text_everywhere(payload))
    check_html_policy(html)
    if any(c in payload for c in "<>\"'"):
        assert payload not in html
    assert "<script" not in html
    assert 'href="https://evil.example' not in html
    assert "\u0000" not in html and "‮" not in html


def test_template_syntax_stays_literal() -> None:
    html = html_of(with_text_everywhere("{{ 7*7 }}"))
    assert "{{ 7*7 }}" in html and ">49<" not in html


# --- templates: separate registry, Phase 5 untouched -------------------------------------------


def test_retest_template_matches_its_lockfile_and_phase5_registry_is_untouched() -> None:
    assert set(retest_locked_hashes()) == {t.key for t in RETEST_TEMPLATES.values()}
    for template in RETEST_TEMPLATES.values():
        assert verified_retest_hash(template) == retest_locked_hashes()[template.key]
    assert set(TEMPLATES) == {("sv-standard", 1)}
    assert set(locked_hashes()) == {"sv-standard@1"}
    assert locked_hashes()["sv-standard@1"] == compute_hash(TEMPLATES[("sv-standard", 1)])


# Pinned from the Phase 5 code at commit a5e767c (unchanged since): Phase 7
# must not alter a single byte of Phase 5 output or the sv-standard@1 lock.
PHASE5_TEMPLATE_HASH = "24c29bad712bfac6e59884b7dd3e3272365c9f2b6819415c1941895fafd85436"
PHASE5_RENDER_SHA256 = {
    "json": "1c37b254f912bddbaa523672c2bdb5995c5114e2536b7d0bab0d14aceb22cc84",
    "html": "58abda356aa41bf15c1ade5b0bc94cf69cb2c0232086e5f2461d3491287d2425",
}


def test_phase5_output_is_byte_identical() -> None:
    from sentinel_reports import render_report
    from tests.factory import snapshot as phase5_snapshot

    assert locked_hashes() == {"sv-standard@1": PHASE5_TEMPLATE_HASH}
    assert compute_hash(TEMPLATES[("sv-standard", 1)]) == PHASE5_TEMPLATE_HASH
    rendered = {a.format: a.sha256 for a in render_report(phase5_snapshot(), LOCAL)}
    assert rendered == PHASE5_RENDER_SHA256


def test_an_edited_retest_template_refuses_to_render(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sentinel_reports import templates

    shutil.copytree(templates.TEMPLATES_DIR, tmp_path / "templates")
    page = tmp_path / "templates" / "sv-retest" / "1" / "report.html.j2"
    page.write_text(page.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    monkeypatch.setattr(templates, "TEMPLATES_DIR", tmp_path / "templates")
    with pytest.raises(TemplateMismatch):
        render_retest_report(snapshot(), ["json"])


def test_the_html_policy_runs_on_rendered_retest_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sentinel_reports import templates
    from sentinel_reports.errors import HtmlPolicyViolation

    shutil.copytree(templates.TEMPLATES_DIR, tmp_path / "templates")
    page = tmp_path / "templates" / "sv-retest" / "1" / "report.html.j2"
    page.write_text(
        page.read_text(encoding="utf-8").replace("</body>", "<script>x()</script></body>"),
        encoding="utf-8",
    )
    monkeypatch.setattr(templates, "TEMPLATES_DIR", tmp_path / "templates")
    template = RETEST_TEMPLATES[("sv-retest", 1)]
    monkeypatch.setattr(
        retest_render, "retest_locked_hashes", lambda: {template.key: compute_hash(template)}
    )
    with pytest.raises(HtmlPolicyViolation):
        render_retest_report(snapshot(), ["html"])


# --- PDF (needs Pango) ----------------------------------------------------------------------------


@pytest.mark.pdf
def test_retest_pdf_is_valid_deterministic_and_safe() -> None:
    import io

    from pypdf import PdfReader

    (pdf,) = render_retest_report(snapshot(), ["pdf"])
    (again,) = render_retest_report(snapshot(), ["pdf"])
    assert pdf.content == again.content and pdf.content.startswith(b"%PDF-")
    text = "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(pdf.content)).pages)
    assert "SV-RT-000001" in text and "Not comparable" in text
    assert b"/JavaScript" not in pdf.content and b"/Launch" not in pdf.content


@pytest.mark.pdf
def test_retest_pdf_refuses_resource_fetches() -> None:
    from sentinel_reports import PdfResourceBlocked
    from sentinel_reports.pdf import render_pdf

    with pytest.raises(PdfResourceBlocked):
        render_pdf(
            b'<html><body><img src="http://127.0.0.1:9/x"></body></html>', identifier=b"0" * 16
        )


def test_no_regex_style_attributes_in_output() -> None:
    assert not re.search(r"\sstyle=", html_of(snapshot()))
