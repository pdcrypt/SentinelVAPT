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
from sentinel_analysis.parsing import origin_key, scheme_of
from sentinel_analysis.rules.base import Rule, cwe_ref, wstg_ref

# --- SV-TRN-001 ------------------------------------------------------------------------


def _cleartext(ctx: RuleContext) -> Iterator[Match]:
    for origin in ctx.origins:
        if not origin.startswith("http://"):
            continue
        responses = [r for r in ctx.responses_at(origin) if scheme_of(r.url) == "http"]
        if responses:
            yield Match(
                subject_key=origin,
                origin=origin,
                evidence_ids=ctx.evidence_of(responses),
                affected_count=len(responses),
                details={"responses_over_http": len(responses)},
            )


TRN_001 = Rule(
    RuleMeta(
        id="SV-TRN-001",
        version=1,
        title="Application served over cleartext HTTP",
        category=Category.TRANSPORT,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        detection_type=DetectionType.AUTOMATED_DETECTION,
        subject_type=SubjectType.ORIGIN,
        description="Responses from this origin were delivered over unencrypted HTTP.",
        proves="The origin served the scanned responses over unencrypted HTTP at scan time.",
        does_not_prove=(
            "That sensitive data is transmitted; that HTTPS is unavailable; that traffic can "
            "be intercepted on the real network."
        ),
        remediation=("Serve the application over HTTPS only and redirect HTTP requests to HTTPS."),
        owasp_top10=("A04:2025",),
        wstg=("WSTG-CRYP-03",),
        cwe=(319,),
        references=(wstg_ref("WSTG-CRYP-03"), cwe_ref(319)),
    ),
    _cleartext,
)

# --- SV-TRN-002 ------------------------------------------------------------------------

# The scanner reports TLS failures as event code "tls_error" with message
# "TLS error: <ssl reason>"; certificate verification failures carry this
# reason (contract pinned by a test against a local self-signed server).
TLS_EVENT_CODE = "tls_error"
CERT_VERIFY_REASON = "CERTIFICATE_VERIFY_FAILED"


def _tls_untrusted(ctx: RuleContext) -> Iterator[Match]:
    counts: dict[str, int] = {}
    for event in ctx.events_with_code(TLS_EVENT_CODE):
        if CERT_VERIFY_REASON not in event.message or not event.url:
            continue
        origin = origin_key(event.url)
        if origin is None or not origin.startswith("https://"):
            continue
        counts[origin] = counts.get(origin, 0) + 1
    for origin in sorted(counts):
        yield Match(
            subject_key=origin,
            origin=origin,
            affected_count=counts[origin],
            details={"reason": CERT_VERIFY_REASON, "failed_requests": counts[origin]},
        )


TRN_002 = Rule(
    RuleMeta(
        id="SV-TRN-002",
        version=1,
        title="TLS certificate could not be verified",
        category=Category.TRANSPORT,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        detection_type=DetectionType.MANUAL_VERIFICATION_REQUIRED,
        subject_type=SubjectType.ORIGIN,
        description=(
            "With certificate verification enabled, the TLS handshake to this origin failed "
            "certificate verification."
        ),
        proves=(
            "With verification on, the TLS handshake to this host and port failed certificate "
            "verification against the scanner host's trust store."
        ),
        does_not_prove=(
            "Which defect it is (self-signed, expired, wrong name, unknown CA); that users' "
            "browsers would distrust it; that interception is possible; anything about "
            "protocol or cipher strength."
        ),
        remediation=(
            "Inspect the certificate. If the service is meant to be trusted by clients, serve "
            "a valid certificate for this hostname from a CA those clients trust."
        ),
        wstg=("WSTG-CRYP-01",),
        references=(wstg_ref("WSTG-CRYP-01"),),
    ),
    _tls_untrusted,
)

RULES = (TRN_001, TRN_002)
