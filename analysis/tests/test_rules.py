"""Per-rule behaviour: positive, negative, malformed and redacted inputs."""

from collections.abc import Sequence

import pytest
from sentinel_analysis import analyze
from sentinel_analysis.model import FindingCandidate
from sentinel_analysis.observations import REDACTED, ScanObservations
from sentinel_analysis.rules import REGISTRY

from tests.builders import SECURE_HEADERS, Page, build, cookie, tls_event

RULES = {rule.meta.id: rule for rule in REGISTRY}


def run(rule_id: str, obs: ScanObservations) -> list[FindingCandidate]:
    result = analyze(obs, rules=[RULES[rule_id]])
    assert result.rule_errors == ()
    return list(result.candidates)


def secure(*extra: tuple[str, str]) -> list[tuple[str, str]]:
    return [*SECURE_HEADERS, *extra]


def without(
    name: str, headers: Sequence[tuple[str, str]] = SECURE_HEADERS
) -> list[tuple[str, str]]:
    return [h for h in headers if h[0].lower() != name.lower()]


# --- SV-TRN-001 cleartext HTTP ---------------------------------------------------------


def test_trn_001_fires_per_http_origin() -> None:
    pages = [Page("http://lab.test/"), Page("http://lab.test/a"), Page("https://lab.test/")]
    [finding] = run("SV-TRN-001", build(pages))
    assert finding.subject_key == "http://lab.test:80"
    assert finding.affected_count == 2
    assert set(finding.evidence_ids) == {pages[0].evidence_id, pages[1].evidence_id}


def test_trn_001_silent_for_https_only() -> None:
    assert run("SV-TRN-001", build([Page("https://lab.test/")])) == []
    assert run("SV-TRN-001", build([])) == []


# --- SV-TRN-002 TLS certificate ----------------------------------------------------------


def test_trn_002_fires_only_on_certificate_verification_failure() -> None:
    events = [tls_event("https://lab.test/"), tls_event("https://lab.test/x")]
    [finding] = run("SV-TRN-002", build([], events=events))
    assert finding.subject_key == "https://lab.test:443"
    assert finding.affected_count == 2
    assert finding.details["reason"] == "CERTIFICATE_VERIFY_FAILED"
    assert finding.evidence_ids == ()  # nothing was fetched


@pytest.mark.parametrize(
    "event",
    [
        tls_event("https://lab.test/", reason="WRONG_VERSION_NUMBER"),  # not TLS on that port
        tls_event("https://lab.test/", reason="SSLV3_ALERT_HANDSHAKE_FAILURE"),
        tls_event("http://lab.test/"),  # not an https origin
        tls_event("not a url"),
    ],
)
def test_trn_002_ignores_other_tls_errors(event: object) -> None:
    assert run("SV-TRN-002", build([], events=[event])) == []  # type: ignore[list-item]


def test_trn_002_never_manufactured_when_trust_was_not_evaluated() -> None:
    result = analyze(build([Page("https://lab.test/")], allow_untrusted_tls=True))
    assert not [c for c in result.candidates if c.rule_id == "SV-TRN-002"]
    assert "tls_trust_not_evaluated" in result.coverage_notes


# --- SV-HDR-001 HSTS -------------------------------------------------------------------


@pytest.mark.parametrize(
    "hsts",
    [None, "max-age=0", "includeSubDomains", "max-age=abc", "max-age=1; max-age=2"],
)
def test_hdr_001_fires_for_missing_or_ineffective(hsts: str | None) -> None:
    headers = without("Strict-Transport-Security")
    if hsts is not None:
        headers.append(("Strict-Transport-Security", hsts))
    [finding] = run("SV-HDR-001", build([Page("https://lab.test/", headers=headers)]))
    assert finding.subject_key == "https://lab.test:443"


def test_hdr_001_negative_cases() -> None:
    assert run("SV-HDR-001", build([Page("https://lab.test/", headers=secure())])) == []
    # Plain HTTP responses are out of scope for HSTS (covered by SV-TRN-001).
    assert run("SV-HDR-001", build([Page("http://lab.test/", headers=[])])) == []
    # A redacted value is present-but-unknown: never reported as missing.
    redacted = [*without("Strict-Transport-Security"), ("Strict-Transport-Security", REDACTED)]
    assert run("SV-HDR-001", build([Page("https://lab.test/", headers=redacted)])) == []


def test_hdr_001_counts_only_lacking_responses() -> None:
    good = Page("https://lab.test/", headers=secure())
    bad = Page("https://lab.test/x", headers=without("Strict-Transport-Security"))
    [finding] = run("SV-HDR-001", build([good, bad]))
    assert finding.evidence_ids == (bad.evidence_id,)
    assert finding.details == {"responses_checked": 2, "responses_lacking": 1}


# --- SV-HDR-002 CSP ----------------------------------------------------------------------


def test_hdr_002_fires_without_enforced_csp() -> None:
    report_only = [
        *without("Content-Security-Policy"),
        ("Content-Security-Policy-Report-Only", "default-src 'self'"),
    ]
    for headers in (without("Content-Security-Policy"), report_only):
        [finding] = run("SV-HDR-002", build([Page("http://lab.test/", headers=headers)]))
        assert finding.subject_key == "http://lab.test:80"


def test_hdr_002_only_html_success_responses() -> None:
    headers = without("Content-Security-Policy")
    assert (
        run("SV-HDR-002", build([Page("http://lab.test/api", html=False, headers=headers)])) == []
    )
    assert run("SV-HDR-002", build([Page("http://lab.test/", status=404, headers=headers)])) == []
    assert run("SV-HDR-002", build([Page("http://lab.test/", headers=secure())])) == []


# --- SV-HDR-003 framing ------------------------------------------------------------------


def test_hdr_003_fires_without_any_framing_protection() -> None:
    headers = [("Content-Security-Policy", "default-src 'self'")]
    [finding] = run("SV-HDR-003", build([Page("http://lab.test/", headers=headers)]))
    assert finding.subject_key == "http://lab.test:80"


@pytest.mark.parametrize(
    "headers",
    [
        [("X-Frame-Options", "DENY")],
        [("X-Frame-Options", "sameorigin")],
        [("Content-Security-Policy", "frame-ancestors 'self'")],
        [("X-Frame-Options", REDACTED)],
    ],
)
def test_hdr_003_negative(headers: list[tuple[str, str]]) -> None:
    assert run("SV-HDR-003", build([Page("http://lab.test/", headers=headers)])) == []


def test_hdr_003_malformed_xfo_is_not_protection() -> None:
    for value in ("ALLOW-FROM https://x", "garbage", ""):
        assert run(
            "SV-HDR-003", build([Page("http://lab.test/", headers=[("X-Frame-Options", value)])])
        )


# --- SV-HDR-004 nosniff ------------------------------------------------------------------


def test_hdr_004() -> None:
    assert run("SV-HDR-004", build([Page("http://lab.test/", headers=[])]))
    assert run(
        "SV-HDR-004",
        build([Page("http://lab.test/", headers=[("X-Content-Type-Options", "sniff")])]),
    )
    assert not run(
        "SV-HDR-004",
        build([Page("http://lab.test/", headers=[("X-Content-Type-Options", "nosniff")])]),
    )
    assert not run(
        "SV-HDR-004",
        build([Page("http://lab.test/", headers=[("X-Content-Type-Options", REDACTED)])]),
    )
    assert not run("SV-HDR-004", build([Page("http://lab.test/", status=301, headers=[])]))


# --- Cookies -----------------------------------------------------------------------------


def test_cke_001_session_like_without_httponly() -> None:
    page = Page(
        "http://lab.test/",
        cookies=[cookie("PHPSESSID"), cookie("theme"), cookie("sid", http_only=True)],
    )
    [finding] = run("SV-CKE-001", build([page]))
    assert (finding.subject_key, finding.discriminator) == ("http://lab.test:80", "PHPSESSID")
    assert finding.evidence_ids == (page.evidence_id,)
    assert finding.confidence.value == "medium"


def test_cke_001_aggregates_per_origin_and_name() -> None:
    pages = [Page(f"http://lab.test/{i}", cookies=[cookie("app_session")]) for i in range(3)]
    [finding] = run("SV-CKE-001", build(pages))
    assert finding.affected_count == 3 and len(finding.evidence_ids) == 3


def test_cke_002_secure_only_matters_over_https() -> None:
    https = Page("https://lab.test/", cookies=[cookie("pref"), cookie("ok", secure=True)])
    http = Page("http://lab.test/", cookies=[cookie("pref")])
    [finding] = run("SV-CKE-002", build([https, http]))
    assert (finding.subject_key, finding.discriminator) == ("https://lab.test:443", "pref")


def test_cke_003_missing_samesite() -> None:
    page = Page(
        "http://lab.test/",
        cookies=[cookie("a"), cookie("b", same_site="Lax"), cookie("c", same_site="")],
    )
    findings = run("SV-CKE-003", build([page]))
    assert sorted(f.discriminator for f in findings) == ["a", "c"]
    assert all(f.severity.value == "informational" for f in findings)


# --- Disclosure --------------------------------------------------------------------------


def test_inf_001_version_disclosure_identity_excludes_the_value() -> None:
    v1 = run("SV-INF-001", build([Page("http://lab.test/", headers=[("Server", "nginx/1.25.3")])]))
    v2 = run("SV-INF-001", build([Page("http://lab.test/", headers=[("Server", "nginx/1.27.0")])]))
    assert [f.fingerprint for f in v1] == [f.fingerprint for f in v2]
    assert v1[0].details["value"] == "nginx/1.25.3"
    assert v1[0].discriminator == "server"


def test_inf_001_negative_and_multiple_headers() -> None:
    assert run("SV-INF-001", build([Page("http://lab.test/", headers=[("Server", "nginx")])])) == []
    assert (
        run("SV-INF-001", build([Page("http://lab.test/", headers=[("Server", REDACTED)])])) == []
    )
    both = [("Server", "Apache/2.4.41"), ("X-Powered-By", "PHP/8.2.1"), ("Via", "1.1 proxy")]
    findings = run("SV-INF-001", build([Page("http://lab.test/", headers=both)]))
    assert sorted(f.discriminator for f in findings) == ["server", "x-powered-by"]


def test_inf_002_error_text() -> None:
    page = Page(
        "http://lab.test/boom", status=500, body="<pre>Traceback (most recent call last):\n</pre>"
    )
    [finding] = run("SV-INF-002", build([page]))
    assert finding.subject_key == "GET http://lab.test/boom"
    assert finding.endpoint_id == page.endpoint_id
    assert finding.details["markers"] == "python_traceback"
    assert run("SV-INF-002", build([Page("http://lab.test/", body="All fine")])) == []


def test_inf_002_only_reads_the_stored_excerpt() -> None:
    # Text beyond the excerpt was never stored, so it cannot be matched.
    page = Page("http://lab.test/", body="x" * 9000 + "Traceback (most recent call last)")
    assert run("SV-INF-002", build([page])) == []


def test_inf_003_directory_listing() -> None:
    listing = Page("http://lab.test/files/", title="Index of /files/")
    [finding] = run("SV-INF-003", build([listing]))
    assert finding.subject_key == "GET http://lab.test/files/"
    assert (
        run("SV-INF-003", build([Page("http://lab.test/", title="Index of /", status=404)])) == []
    )
    assert (
        run("SV-INF-003", build([Page("http://lab.test/", title="Index of /", html=False)])) == []
    )


# --- CORS and methods ----------------------------------------------------------------------


def test_cor_001_wildcard() -> None:
    page = Page("http://lab.test/api", html=False, headers=[("Access-Control-Allow-Origin", " * ")])
    [finding] = run("SV-COR-001", build([page]))
    assert finding.detection_type.value == "manual_verification_required"
    for value in ("https://lab.test", "null", REDACTED):
        assert (
            run(
                "SV-COR-001",
                build([Page("http://lab.test/", headers=[("Access-Control-Allow-Origin", value)])]),
            )
            == []
        )


def test_mth_001_risky_allow_only_on_options() -> None:
    options = Page(
        "http://lab.test/", method="OPTIONS", headers=[("Allow", "GET, HEAD, PUT, TRACE")]
    )
    get = Page("http://lab.test/", headers=[("Allow", "PUT, DELETE")])
    [finding] = run("SV-MTH-001", build([options, get]))
    assert finding.subject_key == "OPTIONS http://lab.test/"
    assert finding.details["advertised_risky_methods"] == "PUT,TRACE"
    safe = Page(
        "http://lab.test/", method="OPTIONS", headers=[("Allow", "GET, HEAD, OPTIONS, POST")]
    )
    assert run("SV-MTH-001", build([safe])) == []
    garbage = Page(
        "http://lab.test/", method="OPTIONS", headers=[("Allow", "PUT;DELETE, <script>")]
    )
    assert run("SV-MTH-001", build([garbage])) == []


# --- Secrets never surface -----------------------------------------------------------------


def test_findings_carry_no_body_or_cookie_values() -> None:
    page = Page(
        "http://lab.test/",
        status=500,
        headers=[("Server", "nginx/1.25.3")],
        body="Traceback (most recent call last): password=[REDACTED] token sk_live_should_not_leak",
        cookies=[cookie("PHPSESSID")],
    )
    result = analyze(build([page]))
    dump = repr(result)
    assert "sk_live_should_not_leak" not in dump
    assert "Traceback (most recent call last)" not in dump  # only marker names are kept
