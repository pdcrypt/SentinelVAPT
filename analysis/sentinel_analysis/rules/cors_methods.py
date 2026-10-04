from collections.abc import Iterator

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
from sentinel_analysis.parsing import origin_key, parse_allow
from sentinel_analysis.rules.base import Rule, wstg_ref

# --- SV-COR-001 ---------------------------------------------------------------------------


def _wildcard_acao(ctx: RuleContext) -> Iterator[Match]:
    for origin in ctx.origins:
        hits = [
            r
            for r in ctx.responses_at(origin)
            if any(v.strip() == "*" for v in ctx.header_values(r, "access-control-allow-origin"))
        ]
        if hits:
            yield Match(
                subject_key=origin,
                origin=origin,
                evidence_ids=ctx.evidence_of(hits),
                affected_count=len(hits),
                details={"responses_with_wildcard": len(hits)},
            )


COR_001 = Rule(
    RuleMeta(
        id="SV-COR-001",
        version=1,
        title="Access-Control-Allow-Origin: * returned",
        category=Category.CORS,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        detection_type=DetectionType.MANUAL_VERIFICATION_REQUIRED,
        subject_type=SubjectType.ORIGIN,
        description=(
            "Responses returned Access-Control-Allow-Origin: *, allowing any origin to read "
            "them from a browser. This is often intended for public resources."
        ),
        proves=(
            "Responses to requests without an Origin header returned "
            "Access-Control-Allow-Origin: *."
        ),
        does_not_prove=(
            "Behaviour for real cross-origin requests; credentialed access (browsers forbid "
            "'*' with credentials, and that header's value is redacted); that the data is "
            "sensitive."
        ),
        remediation=(
            "Return Access-Control-Allow-Origin only for origins that need access, unless "
            "the resource is intentionally public."
        ),
        wstg=("WSTG-CLNT-07",),
        references=(wstg_ref("WSTG-CLNT-07"),),
    ),
    _wildcard_acao,
)

# --- SV-MTH-001 ---------------------------------------------------------------------------

RISKY_METHODS = frozenset({"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"})


def _risky_allow(ctx: RuleContext) -> Iterator[Match]:
    for response in ctx.responses:
        if response.method != "OPTIONS":
            continue
        endpoint = ctx.endpoint(response.endpoint_id)
        if endpoint is None:
            continue
        risky: set[str] = set()
        for value in ctx.header_values(response, "allow"):
            risky |= parse_allow(value) & RISKY_METHODS
        if risky:
            yield Match(
                subject_key=f"{endpoint.method} {endpoint.url}",
                origin=origin_key(endpoint.url),
                endpoint_id=endpoint.id,
                evidence_ids=(response.evidence_id,),
                details={"advertised_risky_methods": ",".join(sorted(risky))},
            )


MTH_001 = Rule(
    RuleMeta(
        id="SV-MTH-001",
        version=1,
        title="Potentially risky methods advertised in Allow",
        category=Category.HTTP_METHODS,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        detection_type=DetectionType.MANUAL_VERIFICATION_REQUIRED,
        subject_type=SubjectType.ENDPOINT,
        description=(
            "An OPTIONS response advertised PUT, DELETE, TRACE, CONNECT or PATCH in its Allow "
            "header. The Allow header often does not reflect what is actually enabled."
        ),
        proves=("An OPTIONS response's Allow header listed PUT, DELETE, TRACE, CONNECT or PATCH."),
        does_not_prove=(
            "That those methods are implemented, enabled, unauthenticated or harmful. No such "
            "request is ever sent by the scanner."
        ),
        remediation=(
            "Disable methods the application does not need and make sure the Allow header is "
            "accurate; verify manually in an authorized test."
        ),
        wstg=("WSTG-CONF-06",),
        references=(wstg_ref("WSTG-CONF-06"),),
    ),
    _risky_allow,
)

RULES = (COR_001, MTH_001)
