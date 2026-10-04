"""Security header rules. Aggregated per origin.

A header whose value is "[REDACTED]" is treated as present but unknown, so a
rule never reports it as missing.
"""

from collections.abc import Callable, Iterator

from sentinel_analysis.context import RuleContext
from sentinel_analysis.model import (
    Category,
    Confidence,
    DetectionType,
    Match,
    RuleMeta,
    Severity,
    SubjectType,
)
from sentinel_analysis.observations import REDACTED, ResponseObs
from sentinel_analysis.parsing import (
    csp_directives,
    frame_options_protective,
    is_nosniff,
    parse_hsts,
    scheme_of,
)
from sentinel_analysis.rules.base import Rule, cwe_ref, wstg_ref


def _per_origin(
    ctx: RuleContext,
    applies: Callable[[ResponseObs], bool],
    lacks: Callable[[ResponseObs], bool],
) -> Iterator[Match]:
    for origin in ctx.origins:
        checked = [r for r in ctx.responses_at(origin) if applies(r)]
        lacking = [r for r in checked if lacks(r)]
        if lacking:
            yield Match(
                subject_key=origin,
                origin=origin,
                evidence_ids=ctx.evidence_of(lacking),
                affected_count=len(lacking),
                details={"responses_checked": len(checked), "responses_lacking": len(lacking)},
            )


# --- SV-HDR-001 HSTS ---------------------------------------------------------------------


def _hsts_ineffective(ctx: RuleContext, response: ResponseObs) -> bool:
    value = ctx.header(response, "strict-transport-security")
    if value is None:
        return True
    if value.strip() == REDACTED:
        return False
    return not parse_hsts(value).effective


def _hsts(ctx: RuleContext) -> Iterator[Match]:
    yield from _per_origin(
        ctx,
        applies=lambda r: scheme_of(r.url) == "https",
        lacks=lambda r: _hsts_ineffective(ctx, r),
    )


HDR_001 = Rule(
    RuleMeta(
        id="SV-HDR-001",
        version=1,
        title="HSTS missing or ineffective on HTTPS responses",
        category=Category.HEADERS,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        detection_type=DetectionType.AUTOMATED_DETECTION,
        subject_type=SubjectType.ORIGIN,
        description=(
            "HTTPS responses from this origin had no Strict-Transport-Security header, or one "
            "that is invalid or has max-age=0."
        ),
        proves=(
            "The observed HTTPS responses had no Strict-Transport-Security header, or it had "
            "max-age=0 or an invalid value."
        ),
        does_not_prove=(
            "That downgrade or stripping attacks are feasible; HSTS preload status; the "
            "behaviour of pages that were not fetched."
        ),
        remediation=(
            "Send Strict-Transport-Security with a positive max-age on all HTTPS responses."
        ),
        wstg=("WSTG-CONF-07",),
        references=(wstg_ref("WSTG-CONF-07"),),
    ),
    _hsts,
)

# --- SV-HDR-002 CSP ----------------------------------------------------------------------


def _csp(ctx: RuleContext) -> Iterator[Match]:
    yield from _per_origin(
        ctx,
        applies=lambda r: ctx.is_html(r) and ctx.is_success(r),
        # Content-Security-Policy-Report-Only does not enforce anything.
        lacks=lambda r: ctx.header(r, "content-security-policy") is None,
    )


HDR_002 = Rule(
    RuleMeta(
        id="SV-HDR-002",
        version=1,
        title="No enforced Content-Security-Policy on HTML responses",
        category=Category.HEADERS,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        detection_type=DetectionType.AUTOMATED_DETECTION,
        subject_type=SubjectType.ORIGIN,
        description=(
            "Successful HTML responses from this origin had no enforced "
            "Content-Security-Policy header (a report-only policy does not count)."
        ),
        proves=(
            "The observed HTML responses had no enforced Content-Security-Policy header "
            "(report-only or no header)."
        ),
        does_not_prove=(
            "That any injection (XSS) exists; policies delivered through <meta> tags; the "
            "quality of any policy that is present."
        ),
        remediation=(
            "Define a Content-Security-Policy suited to the application and send it on HTML "
            "responses."
        ),
    ),
    _csp,
)

# --- SV-HDR-003 framing ------------------------------------------------------------------


def _frame_protected(ctx: RuleContext, response: ResponseObs) -> bool:
    xfo = ctx.header(response, "x-frame-options")
    if xfo is not None and (xfo.strip() == REDACTED or frame_options_protective(xfo)):
        return True
    csp = ctx.header(response, "content-security-policy")
    return csp is not None and (csp.strip() == REDACTED or "frame-ancestors" in csp_directives(csp))


def _framing(ctx: RuleContext) -> Iterator[Match]:
    yield from _per_origin(
        ctx,
        applies=lambda r: ctx.is_html(r) and ctx.is_success(r),
        lacks=lambda r: not _frame_protected(ctx, r),
    )


HDR_003 = Rule(
    RuleMeta(
        id="SV-HDR-003",
        version=1,
        title="No framing protection on HTML responses",
        category=Category.HEADERS,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        detection_type=DetectionType.AUTOMATED_DETECTION,
        subject_type=SubjectType.ORIGIN,
        description=(
            "Successful HTML responses from this origin had neither X-Frame-Options "
            "(DENY/SAMEORIGIN) nor a Content-Security-Policy frame-ancestors directive."
        ),
        proves=("The observed HTML responses had neither X-Frame-Options nor CSP frame-ancestors."),
        does_not_prove=(
            "That a page offers sensitive one-click actions; that clickjacking is practical; "
            "JavaScript frame-busting."
        ),
        remediation=(
            "Send Content-Security-Policy: frame-ancestors 'self' (or 'none'), and/or "
            "X-Frame-Options: DENY or SAMEORIGIN."
        ),
        wstg=("WSTG-CLNT-09",),
        cwe=(1021,),
        references=(wstg_ref("WSTG-CLNT-09"), cwe_ref(1021)),
    ),
    _framing,
)

# --- SV-HDR-004 nosniff ------------------------------------------------------------------


def _nosniff_missing(ctx: RuleContext, response: ResponseObs) -> bool:
    value = ctx.header(response, "x-content-type-options")
    if value is None:
        return True
    return value.strip() != REDACTED and not is_nosniff(value)


def _nosniff(ctx: RuleContext) -> Iterator[Match]:
    yield from _per_origin(
        ctx,
        applies=lambda r: ctx.is_success(r),
        lacks=lambda r: _nosniff_missing(ctx, r),
    )


HDR_004 = Rule(
    RuleMeta(
        id="SV-HDR-004",
        version=1,
        title="X-Content-Type-Options: nosniff missing",
        category=Category.HEADERS,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        detection_type=DetectionType.AUTOMATED_DETECTION,
        subject_type=SubjectType.ORIGIN,
        description=(
            "Successful responses from this origin lacked X-Content-Type-Options: nosniff."
        ),
        proves="The observed responses lacked X-Content-Type-Options: nosniff.",
        does_not_prove=(
            "That content-type sniffing is exploitable; that user-controlled content is served."
        ),
        remediation="Send X-Content-Type-Options: nosniff on all responses.",
    ),
    _nosniff,
)

RULES = (HDR_001, HDR_002, HDR_003, HDR_004)
