"""Cookie attribute rules. One finding per (origin, cookie name).

Cookie values are never seen here: the scanner stores names and attributes only.
"""

from collections.abc import Callable, Iterator

from sentinel_analysis.context import CookieSite, RuleContext
from sentinel_analysis.heuristics import is_session_like_cookie
from sentinel_analysis.model import (
    Category,
    Confidence,
    DetectionType,
    Match,
    RuleMeta,
    Severity,
    SubjectType,
)
from sentinel_analysis.rules.base import Rule, cwe_ref, wstg_ref


def _per_cookie(ctx: RuleContext, matches: Callable[[CookieSite], bool]) -> Iterator[Match]:
    grouped: dict[tuple[str, str], list[CookieSite]] = {}
    for site in ctx.cookie_sites:
        if matches(site):
            grouped.setdefault((site.origin, site.cookie.name), []).append(site)
    for (origin, name), sites in sorted(grouped.items()):
        responses = [r for s in sites for r in ctx.responses_for_endpoint(s.endpoint.id)]
        yield Match(
            subject_key=origin,
            discriminator=name,
            origin=origin,
            evidence_ids=ctx.evidence_of(responses),
            affected_count=len(sites),
            details={"cookie": name, "set_by_endpoints": len(sites)},
        )


# --- SV-CKE-001 --------------------------------------------------------------------------

CKE_001 = Rule(
    RuleMeta(
        id="SV-CKE-001",
        version=1,
        title="Session-like cookie without HttpOnly",
        category=Category.COOKIES,
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        detection_type=DetectionType.MANUAL_VERIFICATION_REQUIRED,
        subject_type=SubjectType.ORIGIN,
        description=(
            "A response set a cookie whose name matches the documented session-cookie "
            "heuristic, without the HttpOnly attribute. Whether it is a session identifier "
            "needs to be verified."
        ),
        proves=("A cookie whose name matches the session heuristic was set without HttpOnly."),
        does_not_prove=(
            "That it is a session token; that script injection exists; that it can be stolen."
        ),
        remediation=(
            "If the cookie identifies a session or carries credentials, set HttpOnly so "
            "scripts cannot read it."
        ),
        owasp_top10=("A02:2025",),
        wstg=("WSTG-SESS-02",),
        cwe=(1004,),
        references=(wstg_ref("WSTG-SESS-02"), cwe_ref(1004)),
    ),
    lambda ctx: _per_cookie(
        ctx, lambda s: not s.cookie.http_only and is_session_like_cookie(s.cookie.name)
    ),
)

# --- SV-CKE-002 --------------------------------------------------------------------------

CKE_002 = Rule(
    RuleMeta(
        id="SV-CKE-002",
        version=1,
        title="Cookie set over HTTPS without Secure",
        category=Category.COOKIES,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        detection_type=DetectionType.AUTOMATED_DETECTION,
        subject_type=SubjectType.ORIGIN,
        description="A response delivered over HTTPS set a cookie without the Secure attribute.",
        proves="A cookie was set by an HTTPS response without Secure.",
        does_not_prove=(
            "That an HTTP endpoint exists or is reachable; that the cookie is sensitive."
        ),
        remediation="Set the Secure attribute on cookies issued over HTTPS.",
        owasp_top10=("A02:2025",),
        wstg=("WSTG-SESS-02",),
        cwe=(614,),
        references=(wstg_ref("WSTG-SESS-02"), cwe_ref(614)),
    ),
    lambda ctx: _per_cookie(ctx, lambda s: s.scheme == "https" and not s.cookie.secure),
)

# --- SV-CKE-003 --------------------------------------------------------------------------

CKE_003 = Rule(
    RuleMeta(
        id="SV-CKE-003",
        version=1,
        title="Cookie without a SameSite attribute",
        category=Category.COOKIES,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        detection_type=DetectionType.AUTOMATED_DETECTION,
        subject_type=SubjectType.ORIGIN,
        description=(
            "A cookie was set without a SameSite attribute, so cross-site behaviour depends "
            "on browser defaults."
        ),
        proves="A cookie was set without a SameSite attribute.",
        does_not_prove=(
            "Browser behaviour (defaults differ between browsers); that any request-forgery "
            "attack is possible."
        ),
        remediation="Set an explicit SameSite attribute (Lax or Strict where possible).",
        wstg=("WSTG-SESS-02",),
        cwe=(1275,),
        references=(wstg_ref("WSTG-SESS-02"), cwe_ref(1275)),
    ),
    lambda ctx: _per_cookie(ctx, lambda s: not s.cookie.same_site),
)

RULES = (CKE_001, CKE_002, CKE_003)
