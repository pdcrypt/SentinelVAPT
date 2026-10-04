from collections.abc import Iterator

from sentinel_analysis.context import RuleContext
from sentinel_analysis.heuristics import error_markers_in, looks_like_directory_listing
from sentinel_analysis.model import (
    Category,
    Confidence,
    DetectionType,
    Match,
    RuleMeta,
    Severity,
    SubjectType,
)
from sentinel_analysis.observations import REDACTED
from sentinel_analysis.parsing import has_version, origin_key
from sentinel_analysis.rules.base import Rule, cwe_ref, wstg_ref

# --- SV-INF-001 ---------------------------------------------------------------------------

VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


def _version_disclosure(ctx: RuleContext) -> Iterator[Match]:
    for origin in ctx.origins:
        for header in VERSION_HEADERS:
            hits = [
                (r, v)
                for r in ctx.responses_at(origin)
                for v in ctx.header_values(r, header)
                if v.strip() != REDACTED and has_version(v)
            ]
            if hits:
                values = sorted({v.strip()[:200] for _, v in hits})
                yield Match(
                    subject_key=origin,
                    # Identity is the header, not its value: an upgraded version is
                    # still the same disclosure.
                    discriminator=header,
                    origin=origin,
                    evidence_ids=ctx.evidence_of(r for r, _ in hits),
                    affected_count=len({r.evidence_id for r, _ in hits}),
                    details={"header": header, "value": values[0], "distinct_values": len(values)},
                )


INF_001 = Rule(
    RuleMeta(
        id="SV-INF-001",
        version=1,
        title="Software version disclosed in response headers",
        category=Category.DISCLOSURE,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        detection_type=DetectionType.AUTOMATED_DETECTION,
        subject_type=SubjectType.ORIGIN,
        description=(
            "A Server, X-Powered-By, X-AspNet-Version or X-AspNetMvc-Version header contained "
            "a version-like string."
        ),
        proves="A header advertised a product name with a version-like string.",
        does_not_prove=(
            "That the version is accurate (headers can be spoofed or added by proxies) or "
            "vulnerable; no CVE matching is done."
        ),
        remediation="Remove or genericise version information in response headers.",
        wstg=("WSTG-INFO-02",),
        cwe=(497,),
        references=(wstg_ref("WSTG-INFO-02"), cwe_ref(497)),
    ),
    _version_disclosure,
)

# --- SV-INF-002 ---------------------------------------------------------------------------


def _error_text(ctx: RuleContext) -> Iterator[Match]:
    for response in ctx.responses:
        markers = error_markers_in(response.body_excerpt)
        endpoint = ctx.endpoint(response.endpoint_id)
        if not markers or endpoint is None:
            continue
        yield Match(
            subject_key=f"{endpoint.method} {endpoint.url}",
            origin=origin_key(endpoint.url),
            endpoint_id=endpoint.id,
            evidence_ids=(response.evidence_id,),
            details={
                "markers": ",".join(markers),
                "status": response.status,
                "excerpt_truncated": response.truncated,
            },
        )


INF_002 = Rule(
    RuleMeta(
        id="SV-INF-002",
        version=1,
        title="Error or stack-trace text in a response",
        category=Category.DISCLOSURE,
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        detection_type=DetectionType.MANUAL_VERIFICATION_REQUIRED,
        subject_type=SubjectType.ENDPOINT,
        description=(
            "The stored response excerpt contains text that matches documented error or "
            "stack-trace markers of common platforms."
        ),
        proves=(
            "The stored (at most 2 KiB by default, redacted) excerpt contains text matching "
            "documented error or stack-trace patterns."
        ),
        does_not_prove=(
            "That sensitive internals are exposed; that the error is attacker-triggerable; "
            "that injection exists; anything beyond the stored excerpt."
        ),
        remediation=(
            "Return generic error pages to clients and log details server-side; disable debug "
            "modes outside development."
        ),
        owasp_top10=("A10:2025",),
        wstg=("WSTG-ERRH-01",),
        cwe=(209,),
        references=(wstg_ref("WSTG-ERRH-01"), cwe_ref(209)),
    ),
    _error_text,
)

# --- SV-INF-003 ---------------------------------------------------------------------------


def _directory_listing(ctx: RuleContext) -> Iterator[Match]:
    for response in ctx.responses:
        endpoint = ctx.endpoint(response.endpoint_id)
        if endpoint is None or response.status != 200 or not ctx.is_html(response):
            continue
        if looks_like_directory_listing(endpoint.title, response.body_excerpt):
            yield Match(
                subject_key=f"{endpoint.method} {endpoint.url}",
                origin=origin_key(endpoint.url),
                endpoint_id=endpoint.id,
                evidence_ids=(response.evidence_id,),
                details={"title": (endpoint.title or "")[:200]},
            )


INF_003 = Rule(
    RuleMeta(
        id="SV-INF-003",
        version=1,
        title="Directory listing page",
        category=Category.DISCLOSURE,
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        detection_type=DetectionType.AUTOMATED_DETECTION,
        subject_type=SubjectType.ENDPOINT,
        description=(
            "A successful HTML response matched documented auto-index markers such as a "
            "title starting with 'Index of /'."
        ),
        proves=(
            "A response matched documented directory-index markers (for example a title "
            "'Index of /...')."
        ),
        does_not_prove=(
            "That the listed files are sensitive or downloadable; listing on other paths."
        ),
        remediation="Disable automatic directory indexes on the web server.",
        cwe=(548,),
        references=(cwe_ref(548),),
    ),
    _directory_listing,
)

RULES = (INF_001, INF_002, INF_003)
