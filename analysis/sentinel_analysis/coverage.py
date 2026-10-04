"""Per-rule coverage (ADR 0011): which subjects each rule actually examined.

A rule's coverage is the set of subjects for which the scan contained input the
rule would have evaluated. If a subject is covered and the rule produced no
finding for it, the rule examined that subject and found the condition absent.
That is the only basis on which a comparison may call a finding FIXED.

Rules:

- Each function mirrors the applicability of exactly one rule version. The
  rule definitions themselves are not touched. A rule whose version has no
  matching coverage function has no coverage: its absences are not comparable.
- Coverage is conservative. Responses where a header the rule depends on was
  redacted (present but unknown) do not count as examined, and nothing is
  covered for certificate trust when the scan accepted untrusted TLS.
- Every subject a rule matches is within that rule's coverage (enforced by
  tests), so a finding can never exist on a subject the rule "did not examine".
- Coverage is computed from the same bounded RuleContext the rules use, from
  persisted observations only. No network access.
"""

from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field

from sentinel_analysis.context import CookieSite, RuleContext
from sentinel_analysis.heuristics import is_session_like_cookie
from sentinel_analysis.observations import REDACTED, ResponseObs, ScanObservations
from sentinel_analysis.parsing import has_version, origin_key, scheme_of
from sentinel_analysis.rules import REGISTRY, Rule
from sentinel_analysis.rules.disclosure import VERSION_HEADERS
from sentinel_analysis.rules.transport import CERT_VERIFY_REASON, TLS_EVENT_CODE

# (rule_id, subject_key, discriminator)
CoverageKey = tuple[str, str, str]
# One examined subject: (subject_key, discriminator, evidence ids that prove it)
Examined = tuple[str, str, tuple[str, ...]]
CoverageFn = Callable[[RuleContext], Iterable[Examined]]


@dataclass(frozen=True)
class Coverage:
    """Examined subjects per rule, and the rule versions this coverage is for."""

    keys: Mapping[CoverageKey, tuple[str, ...]] = field(default_factory=dict)
    rules: Mapping[str, int] = field(default_factory=dict)


def _first_value_known(ctx: RuleContext, response: ResponseObs, headers: Iterable[str]) -> bool:
    """For rules that read a header's first value (ctx.header): the response
    was examined unless that value was redacted (present but unknown)."""
    for name in headers:
        value = ctx.header(response, name)
        if value is not None and value.strip() == REDACTED:
            return False
    return True


def _per_origin(
    ctx: RuleContext, applies: Callable[[ResponseObs], bool], headers: tuple[str, ...] = ()
) -> Iterator[Examined]:
    for origin in ctx.origins:
        examined = [
            r
            for r in ctx.responses_at(origin)
            if applies(r) and _first_value_known(ctx, r, headers)
        ]
        if examined:
            yield origin, "", ctx.evidence_of(examined)


def _per_endpoint(ctx: RuleContext, applies: Callable[[ResponseObs], bool]) -> Iterator[Examined]:
    grouped: dict[str, list[ResponseObs]] = {}
    for response in ctx.responses:
        endpoint = ctx.endpoint(response.endpoint_id)
        if endpoint is not None and applies(response):
            grouped.setdefault(f"{endpoint.method} {endpoint.url}", []).append(response)
    for subject in sorted(grouped):
        yield subject, "", ctx.evidence_of(grouped[subject])


def _per_cookie(ctx: RuleContext, applies: Callable[[CookieSite], bool]) -> Iterator[Examined]:
    grouped: dict[tuple[str, str], list[CookieSite]] = {}
    for site in ctx.cookie_sites:
        if applies(site):
            grouped.setdefault((site.origin, site.cookie.name), []).append(site)
    for (origin, name), sites in sorted(grouped.items()):
        responses = [r for s in sites for r in ctx.responses_for_endpoint(s.endpoint.id)]
        yield origin, name, ctx.evidence_of(responses)


# --- one function per rule version ------------------------------------------------------


def _trn_001(ctx: RuleContext) -> Iterator[Examined]:
    for origin in ctx.origins:
        if origin.startswith("http://"):
            responses = [r for r in ctx.responses_at(origin) if scheme_of(r.url) == "http"]
            if responses:
                yield origin, "", ctx.evidence_of(responses)


def _trn_002(ctx: RuleContext) -> Iterator[Examined]:
    # Certificate trust was examined where a handshake ran with verification
    # on: a response over HTTPS (verification succeeded) or a recorded
    # certificate-verification failure (which the rule reports). With untrusted
    # TLS accepted, trust was never examined, so nothing is covered.
    examined: dict[str, tuple[str, ...]] = {}
    for event in ctx.events_with_code(TLS_EVENT_CODE):
        origin = origin_key(event.url) if event.url else None
        if CERT_VERIFY_REASON in event.message and origin and origin.startswith("https://"):
            examined.setdefault(origin, ())
    if ctx.scan.allow_untrusted_tls:
        # Responses prove nothing about trust here; only recorded failures
        # (which the rule reports) count, and they carry no evidence.
        for origin in sorted(examined):
            yield origin, "", ()
        return
    for origin in ctx.origins:
        if origin.startswith("https://"):
            responses = [r for r in ctx.responses_at(origin) if scheme_of(r.url) == "https"]
            if responses:
                examined[origin] = ctx.evidence_of(responses)
    for origin in sorted(examined):
        yield origin, "", examined[origin]


def _hdr_001(ctx: RuleContext) -> Iterator[Examined]:
    yield from _per_origin(
        ctx, lambda r: scheme_of(r.url) == "https", ("strict-transport-security",)
    )


def _html_success(ctx: RuleContext) -> Callable[[ResponseObs], bool]:
    return lambda r: ctx.is_html(r) and ctx.is_success(r)


def _hdr_002(ctx: RuleContext) -> Iterator[Examined]:
    yield from _per_origin(ctx, _html_success(ctx), ("content-security-policy",))


def _hdr_003(ctx: RuleContext) -> Iterator[Examined]:
    yield from _per_origin(ctx, _html_success(ctx), ("x-frame-options", "content-security-policy"))


def _hdr_004(ctx: RuleContext) -> Iterator[Examined]:
    yield from _per_origin(ctx, ctx.is_success, ("x-content-type-options",))


def _cke_001(ctx: RuleContext) -> Iterator[Examined]:
    yield from _per_cookie(ctx, lambda s: is_session_like_cookie(s.cookie.name))


def _cke_002(ctx: RuleContext) -> Iterator[Examined]:
    yield from _per_cookie(ctx, lambda s: s.scheme == "https")


def _cke_003(ctx: RuleContext) -> Iterator[Examined]:
    yield from _per_cookie(ctx, lambda s: True)


def _all_values_known_or_matched(
    ctx: RuleContext, response: ResponseObs, header: str, matched: Callable[[str], bool]
) -> bool:
    """For rules that read every value of a header (ctx.header_values): the
    response was examined if no value was redacted, or if a value matched (the
    rule then reports it, so it can never count towards FIXED)."""
    values = [v.strip() for v in ctx.header_values(response, header)]
    return REDACTED not in values or any(v != REDACTED and matched(v) for v in values)


def _inf_001(ctx: RuleContext) -> Iterator[Examined]:
    for origin in ctx.origins:
        for header in VERSION_HEADERS:
            examined = [
                r
                for r in ctx.responses_at(origin)
                if _all_values_known_or_matched(ctx, r, header, has_version)
            ]
            if examined:
                yield origin, header, ctx.evidence_of(examined)


def _inf_002(ctx: RuleContext) -> Iterator[Examined]:
    # Only responses whose body excerpt was captured were examined.
    yield from _per_endpoint(ctx, lambda r: bool(r.body_excerpt))


def _inf_003(ctx: RuleContext) -> Iterator[Examined]:
    yield from _per_endpoint(ctx, lambda r: r.status == 200 and ctx.is_html(r))


def _cor_001(ctx: RuleContext) -> Iterator[Examined]:
    for origin in ctx.origins:
        examined = [
            r
            for r in ctx.responses_at(origin)
            if _all_values_known_or_matched(
                ctx, r, "access-control-allow-origin", lambda v: v == "*"
            )
        ]
        if examined:
            yield origin, "", ctx.evidence_of(examined)


def _mth_001(ctx: RuleContext) -> Iterator[Examined]:
    yield from _per_endpoint(ctx, lambda r: r.method == "OPTIONS")


# rule id -> (the rule version this coverage function was written for, function)
COVERAGE_FUNCTIONS: dict[str, tuple[int, CoverageFn]] = {
    "SV-TRN-001": (1, _trn_001),
    "SV-TRN-002": (1, _trn_002),
    "SV-HDR-001": (1, _hdr_001),
    "SV-HDR-002": (1, _hdr_002),
    "SV-HDR-003": (1, _hdr_003),
    "SV-HDR-004": (1, _hdr_004),
    "SV-CKE-001": (1, _cke_001),
    "SV-CKE-002": (1, _cke_002),
    "SV-CKE-003": (1, _cke_003),
    "SV-INF-001": (1, _inf_001),
    "SV-INF-002": (1, _inf_002),
    "SV-INF-003": (1, _inf_003),
    "SV-COR-001": (1, _cor_001),
    "SV-MTH-001": (1, _mth_001),
}


def coverage(observations: ScanObservations, rules: Iterable[Rule] = REGISTRY) -> Coverage:
    """Examined subjects of every rule that has a coverage function for its
    exact version. A coverage function that fails leaves its rule uncovered
    (its absences become not comparable) rather than failing the comparison."""
    ctx = RuleContext(observations)
    keys: dict[CoverageKey, tuple[str, ...]] = {}
    covered_rules: dict[str, int] = {}
    for rule in sorted(rules, key=lambda r: r.meta.id):
        entry = COVERAGE_FUNCTIONS.get(rule.meta.id)
        if entry is None or entry[0] != rule.meta.version:
            continue
        try:
            examined = list(entry[1](ctx))
        except Exception:  # noqa: S112  # isolate the rule: no coverage, never FIXED
            continue
        for subject_key, discriminator, evidence in examined:
            keys[(rule.meta.id, subject_key, discriminator)] = tuple(sorted(set(evidence)))
        covered_rules[rule.meta.id] = rule.meta.version
    return Coverage(keys=dict(sorted(keys.items())), rules=covered_rules)
