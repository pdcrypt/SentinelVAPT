"""The analysis engine: observations -> deterministic finding candidates.

- Each rule runs in isolation: an exception, or output that breaks the Match
  contract, is recorded as a rule error and drops only that rule's output.
- Output is validated and bounded: evidence ids must belong to this scan's
  observations, details are small scalar values, counts are capped.
- Matches with the same fingerprint are merged; candidates are sorted, so the
  same observations always produce identical results regardless of input order.
"""

import hashlib
import itertools
from collections.abc import Iterable, Mapping

from sentinel_analysis.context import RuleContext
from sentinel_analysis.fingerprint import fingerprint
from sentinel_analysis.model import (
    AnalysisResult,
    DetailValue,
    FindingCandidate,
    Match,
    RuleError,
    RuleMeta,
)
from sentinel_analysis.observations import ScanObservations
from sentinel_analysis.rules import REGISTRY, Rule

MAX_EVIDENCE_REFS = 25
MAX_MATCHES_PER_RULE = 500
MAX_DETAIL_KEYS = 10
MAX_DETAIL_KEY = 64
MAX_DETAIL_STRING = 300
MAX_SUBJECT_KEY = 2200
MAX_DISCRIMINATOR = 255

COVERAGE_PARTIAL = "partial_scan"  # the scan stopped before completing its crawl
COVERAGE_TLS_NOT_EVALUATED = "tls_trust_not_evaluated"  # allow_untrusted_tls was used
COVERAGE_TRUNCATED = "observations_truncated"  # inputs exceeded the context limits


class RuleContractError(ValueError):
    """A rule produced output that violates the Match contract."""


def ruleset_version(rules: Iterable[Rule] = REGISTRY) -> str:
    digest = hashlib.sha256()
    for rule in sorted(rules, key=lambda r: r.meta.id):
        digest.update(f"{rule.meta.id}@{rule.meta.version}:{rule.meta.metadata_hash()};".encode())
    return f"rs-{digest.hexdigest()[:16]}"


RULESET_VERSION = ruleset_version()


def _validated_details(details: Mapping[str, DetailValue]) -> dict[str, DetailValue]:
    if len(details) > MAX_DETAIL_KEYS:
        raise RuleContractError("too many detail keys")
    clean: dict[str, DetailValue] = {}
    for key, value in details.items():
        if not isinstance(key, str) or not key or len(key) > MAX_DETAIL_KEY:
            raise RuleContractError("invalid detail key")
        if isinstance(value, str):
            clean[key] = value[:MAX_DETAIL_STRING]
        elif value is None or isinstance(value, bool | int):
            clean[key] = value
        else:
            raise RuleContractError("detail values must be str, int, bool or None")
    return dict(sorted(clean.items()))


def _candidate(meta: RuleMeta, match: Match, ctx: RuleContext) -> FindingCandidate:
    if not match.subject_key or len(match.subject_key) > MAX_SUBJECT_KEY:
        raise RuleContractError("invalid subject_key")
    if len(match.discriminator) > MAX_DISCRIMINATOR:
        raise RuleContractError("discriminator too long")
    if match.affected_count < 1:
        raise RuleContractError("affected_count must be positive")
    unknown = set(match.evidence_ids) - ctx.evidence_ids
    if unknown:
        raise RuleContractError("evidence ids not in this scan's observations")
    confidence = meta.confidence
    if match.confidence is not None:
        if match.confidence.rank > meta.confidence.rank:
            raise RuleContractError("a match may only lower the rule's confidence")
        confidence = match.confidence
    return FindingCandidate(
        rule_id=meta.id,
        rule_version=meta.version,
        fingerprint=fingerprint(meta.id, meta.subject_type, match.subject_key, match.discriminator),
        category=meta.category,
        subject_type=meta.subject_type,
        subject_key=match.subject_key,
        discriminator=match.discriminator,
        severity=meta.severity,
        confidence=confidence,
        detection_type=meta.detection_type,
        evidence_ids=tuple(sorted(set(match.evidence_ids)))[:MAX_EVIDENCE_REFS],
        details=_validated_details(match.details),
        affected_count=match.affected_count,
        origin=match.origin,
        endpoint_id=match.endpoint_id,
    )


def _merge(a: FindingCandidate, b: FindingCandidate) -> FindingCandidate:
    """Deterministic merge of two candidates with the same fingerprint."""
    first, second = sorted((a, b), key=lambda c: (c.evidence_ids, sorted(c.details.items())))
    return FindingCandidate(
        **{
            **first.__dict__,
            "evidence_ids": tuple(sorted(set(a.evidence_ids) | set(b.evidence_ids)))[
                :MAX_EVIDENCE_REFS
            ],
            "affected_count": a.affected_count + b.affected_count,
            "confidence": min((a.confidence, b.confidence), key=lambda c: c.rank),
            "details": first.details or second.details,
        }
    )


def analyze(observations: ScanObservations, rules: Iterable[Rule] = REGISTRY) -> AnalysisResult:
    rules = tuple(sorted(rules, key=lambda r: r.meta.id))
    ctx = RuleContext(observations)
    candidates: dict[str, FindingCandidate] = {}
    errors: list[RuleError] = []

    for rule in rules:
        try:
            matches = list(itertools.islice(rule.evaluate(ctx), MAX_MATCHES_PER_RULE + 1))
            if len(matches) > MAX_MATCHES_PER_RULE:
                raise RuleContractError("too many matches")
            produced = [_candidate(rule.meta, m, ctx) for m in matches]
        except Exception as exc:  # isolate the rule; keep only the exception type
            errors.append(RuleError(rule.meta.id, type(exc).__name__))
            continue
        for candidate in produced:
            existing = candidates.get(candidate.fingerprint)
            candidates[candidate.fingerprint] = (
                candidate if existing is None else _merge(existing, candidate)
            )

    notes = []
    if observations.scan.stop_reason not in (None, "completed"):
        notes.append(COVERAGE_PARTIAL)
    if observations.scan.allow_untrusted_tls:
        notes.append(COVERAGE_TLS_NOT_EVALUATED)
    if ctx.truncated:
        notes.append(COVERAGE_TRUNCATED)

    return AnalysisResult(
        ruleset_version=ruleset_version(rules),
        candidates=tuple(sorted(candidates.values(), key=lambda c: (c.rule_id, c.fingerprint))),
        rule_errors=tuple(errors),
        rules_evaluated=tuple(r.meta.id for r in rules),
        coverage_notes=tuple(notes),
    )
