"""Comparison policy cmp-1 (ADR 0011): baseline findings vs current findings.

A pure, deterministic function over plain values: no database, no network, no
clock. The backend loads persisted findings, coverage and chain history, calls
classify(), and stores the records.

Identity is the Phase 4 fingerprint (within one target). There is no fuzzy
matching: a moved endpoint is a different identity.

States, for each fingerprint present in either scan:

- NEW             current finding, no baseline finding (and not previously FIXED)
- REOPENED        current finding, no baseline finding, and the most recent
                  record for this identity in the retest chain was FIXED
- UNCHANGED       both present, no meaningful difference under cmp-1
- STILL_OPEN      both present, with a meaningful difference (reasons say which)
- DISMISSED       baseline finding was triaged false_positive and the current
                  scan has no finding: never FIXED
- NOT_COMPARABLE  baseline finding, no current finding, and the rule context
                  does not permit a safe comparison (rule not evaluated, rule
                  error, different rule version, no coverage for the rule)
- NOT_RETESTED    baseline finding, no current finding, and the current scan
                  did not examine the subject (out of scope or not covered)
- FIXED           baseline finding (not false_positive), no current finding,
                  same rule version evaluated, and the rule's coverage proves
                  it examined the subject. Never inferred from absence alone.

Meaningful difference (cmp-1): rule version, severity, confidence, detection
type, and finding details other than integer counters. Counters such as
responses checked or affected counts vary with crawl size, not with the issue.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from sentinel_analysis.coverage import CoverageKey
from sentinel_analysis.model import DetailValue

POLICY_VERSION = "cmp-1"
MAX_COVERAGE_EVIDENCE = 25

FALSE_POSITIVE = "false_positive"


class State(StrEnum):
    NEW = "new"
    REOPENED = "reopened"
    UNCHANGED = "unchanged"
    STILL_OPEN = "still_open"
    FIXED = "fixed"
    DISMISSED = "dismissed"
    NOT_RETESTED = "not_retested"
    NOT_COMPARABLE = "not_comparable"


REASONS = frozenset(
    {
        # NEW / REOPENED
        "first_observed",
        "previously_fixed",
        "previously_dismissed",
        "previously_not_retested",
        "previously_not_comparable",
        "previously_observed",
        # UNCHANGED / STILL_OPEN
        "rule_version_changed",
        "severity_changed",
        "confidence_changed",
        "detection_type_changed",
        "details_changed",
        "baseline_false_positive",
        # FIXED / DISMISSED / NOT_RETESTED / NOT_COMPARABLE
        "examined_condition_absent",
        "subject_not_observed",
        "out_of_scope",
        "rule_not_evaluated",
        "rule_error",
        "coverage_unavailable",
        "partial_scan",
        "tls_trust_not_evaluated",
        "observations_truncated",
    }
)
_NOTE_REASONS = ("partial_scan", "tls_trust_not_evaluated", "observations_truncated")
_HISTORY_REASONS = {
    State.DISMISSED: "previously_dismissed",
    State.NOT_RETESTED: "previously_not_retested",
    State.NOT_COMPARABLE: "previously_not_comparable",
}


@dataclass(frozen=True)
class FindingSnapshot:
    """A persisted finding as the comparison sees it, with its triage status
    at comparison time."""

    finding_id: str
    fingerprint: str
    rule_id: str
    rule_version: int
    subject_type: str
    subject_key: str
    discriminator: str
    severity: str
    confidence: str
    detection_type: str
    details: Mapping[str, DetailValue]
    triage_status: str

    @property
    def coverage_key(self) -> CoverageKey:
        return (self.rule_id, self.subject_key, self.discriminator)


@dataclass(frozen=True)
class CurrentRun:
    """What the current scan's analysis can prove.

    evaluated_rules: rule id -> version evaluated by the current run, or None if
    that cannot be established (an old run whose rule set is unknown)."""

    evaluated_rules: Mapping[str, int] | None
    rule_errors: frozenset[str] = frozenset()
    coverage: Mapping[CoverageKey, tuple[str, ...]] = field(default_factory=dict)
    coverage_rules: Mapping[str, int] = field(default_factory=dict)
    coverage_notes: frozenset[str] = frozenset()
    out_of_scope: frozenset[str] = frozenset()  # fingerprints of subjects outside current scope


@dataclass(frozen=True)
class ComparisonRecord:
    fingerprint: str
    rule_id: str
    state: State
    reasons: tuple[str, ...]
    baseline: FindingSnapshot | None
    current: FindingSnapshot | None
    coverage_evidence: tuple[str, ...] = ()


def _is_counter(value: DetailValue) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _meaningful(details: Mapping[str, DetailValue]) -> tuple[tuple[str, DetailValue], ...]:
    """Details that describe the issue, without integer counters."""
    return tuple(sorted((k, v) for k, v in details.items() if not _is_counter(v)))


def _both_present(b: FindingSnapshot, c: FindingSnapshot) -> ComparisonRecord:
    reasons = []
    if b.rule_version != c.rule_version:
        reasons.append("rule_version_changed")
    if b.severity != c.severity:
        reasons.append("severity_changed")
    if b.confidence != c.confidence:
        reasons.append("confidence_changed")
    if b.detection_type != c.detection_type:
        reasons.append("detection_type_changed")
    if _meaningful(b.details) != _meaningful(c.details):
        reasons.append("details_changed")
    state = State.STILL_OPEN if reasons else State.UNCHANGED
    if b.triage_status == FALSE_POSITIVE:
        reasons.append("baseline_false_positive")
    return ComparisonRecord(b.fingerprint, b.rule_id, state, tuple(sorted(reasons)), b, c)


def _only_current(c: FindingSnapshot, previous: State | None) -> ComparisonRecord:
    if previous is State.FIXED:
        return ComparisonRecord(
            c.fingerprint, c.rule_id, State.REOPENED, ("previously_fixed",), None, c
        )
    if previous is None:
        reason = "first_observed"
    else:
        reason = _HISTORY_REASONS.get(previous, "previously_observed")
    return ComparisonRecord(c.fingerprint, c.rule_id, State.NEW, (reason,), None, c)


def _only_baseline(b: FindingSnapshot, run: CurrentRun) -> ComparisonRecord:
    evidence = run.coverage.get(b.coverage_key)
    notes = tuple(n for n in _NOTE_REASONS if n in run.coverage_notes)

    def record(state: State, *reasons: str, proof: tuple[str, ...] = ()) -> ComparisonRecord:
        return ComparisonRecord(
            b.fingerprint, b.rule_id, state, tuple(sorted(set(reasons))), b, None, proof
        )

    # A false positive that is no longer reported is DISMISSED: never FIXED.
    if b.triage_status == FALSE_POSITIVE:
        if evidence:
            return record(
                State.DISMISSED,
                "baseline_false_positive",
                "examined_condition_absent",
                proof=evidence[:MAX_COVERAGE_EVIDENCE],
            )
        return record(State.DISMISSED, "baseline_false_positive", "subject_not_observed")

    evaluated = run.evaluated_rules
    if evaluated is None or b.rule_id not in evaluated:
        return record(State.NOT_COMPARABLE, "rule_not_evaluated")
    if b.rule_id in run.rule_errors:
        return record(State.NOT_COMPARABLE, "rule_error")
    if evaluated[b.rule_id] != b.rule_version:
        return record(State.NOT_COMPARABLE, "rule_version_changed")
    if run.coverage_rules.get(b.rule_id) != evaluated[b.rule_id]:
        return record(State.NOT_COMPARABLE, "coverage_unavailable")
    if b.fingerprint in run.out_of_scope:
        return record(State.NOT_RETESTED, "out_of_scope")
    if not evidence:
        # Not examined, or examined without any stored response to show for
        # it: absence alone never makes a finding FIXED.
        return record(State.NOT_RETESTED, "subject_not_observed", *notes)
    return record(State.FIXED, "examined_condition_absent", proof=evidence[:MAX_COVERAGE_EVIDENCE])


def _index(findings: Iterable[FindingSnapshot], which: str) -> dict[str, FindingSnapshot]:
    indexed: dict[str, FindingSnapshot] = {}
    for finding in findings:
        if finding.fingerprint in indexed:
            raise ValueError(f"duplicate fingerprint in {which} findings")
        indexed[finding.fingerprint] = finding
    return indexed


def classify(
    baseline: Iterable[FindingSnapshot],
    current: Iterable[FindingSnapshot],
    run: CurrentRun,
    history: Mapping[str, State],
) -> tuple[ComparisonRecord, ...]:
    """One record per fingerprint present in either scan, sorted by
    fingerprint. `history` maps a fingerprint to the state of its most recent
    record in the retest chain's earlier comparisons."""
    old = _index(baseline, "baseline")
    new = _index(current, "current")
    records = []
    for fp in sorted(old.keys() | new.keys()):
        b, c = old.get(fp), new.get(fp)
        if b is not None and c is not None:
            records.append(_both_present(b, c))
        elif c is not None:
            records.append(_only_current(c, history.get(fp)))
        elif b is not None:
            records.append(_only_baseline(b, run))
    for r in records:
        if not set(r.reasons) <= REASONS:  # pragma: no cover  # internal invariant
            raise ValueError("unknown comparison reason")
    return tuple(records)


def summarize(records: Iterable[ComparisonRecord]) -> dict[str, int]:
    counts = {state.value: 0 for state in State}
    for record in records:
        counts[record.state.value] += 1
    return counts
