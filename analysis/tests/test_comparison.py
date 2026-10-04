"""Comparison policy cmp-1: the classification matrix, ordering and invariants."""

import random
from dataclasses import replace
from typing import Any

import pytest
from sentinel_analysis.comparison import (
    MAX_COVERAGE_EVIDENCE,
    POLICY_VERSION,
    REASONS,
    CurrentRun,
    FindingSnapshot,
    State,
    classify,
    summarize,
)

ORIGIN = "http://127.0.0.1:8080"
RULES = {"SV-HDR-002": 1, "SV-INF-001": 1, "SV-INF-002": 1}


def finding(fp: str = "a" * 64, **kw: Any) -> FindingSnapshot:
    values: dict[str, Any] = {
        "finding_id": f"f-{fp[:4]}",
        "fingerprint": fp,
        "rule_id": "SV-HDR-002",
        "rule_version": 1,
        "subject_type": "origin",
        "subject_key": ORIGIN,
        "discriminator": "",
        "severity": "low",
        "confidence": "high",
        "detection_type": "automated_detection",
        "details": {"responses_checked": 3, "responses_lacking": 3},
        "triage_status": "open",
    }
    values.update(kw)
    return FindingSnapshot(**values)


def run(**kw: Any) -> CurrentRun:
    values: dict[str, Any] = {
        "evaluated_rules": RULES,
        "coverage": {("SV-HDR-002", ORIGIN, ""): ("ev-1", "ev-2")},
        "coverage_rules": RULES,
    }
    values.update(kw)
    return CurrentRun(**values)


def one(baseline: list[FindingSnapshot], current: list[FindingSnapshot], **kw: Any) -> Any:
    history = kw.pop("history", {})
    (record,) = classify(baseline, current, run(**kw), history)
    return record


def test_policy_identifier() -> None:
    assert POLICY_VERSION == "cmp-1"


# --- present in the current scan --------------------------------------------------------


def test_new() -> None:
    r = one([], [finding()])
    assert (r.state, r.reasons) == (State.NEW, ("first_observed",))
    assert r.baseline is None and r.current is not None


def test_reopened_requires_fixed_history() -> None:
    assert one([], [finding()], history={"a" * 64: State.FIXED}).state is State.REOPENED
    for previous, reason in [
        (State.DISMISSED, "previously_dismissed"),
        (State.NOT_RETESTED, "previously_not_retested"),
        (State.NOT_COMPARABLE, "previously_not_comparable"),
        (State.UNCHANGED, "previously_observed"),
    ]:
        r = one([], [finding()], history={"a" * 64: previous})
        assert (r.state, r.reasons) == (State.NEW, (reason,)), previous


def test_unchanged_ignores_counters_and_evidence() -> None:
    b = finding(details={"responses_checked": 3, "responses_lacking": 3})
    c = finding(finding_id="other", details={"responses_checked": 9, "responses_lacking": 1})
    r = one([b], [c])
    assert (r.state, r.reasons) == (State.UNCHANGED, ())


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"severity": "informational"}, "severity_changed"),
        ({"confidence": "medium"}, "confidence_changed"),
        ({"detection_type": "manual_verification_required"}, "detection_type_changed"),
        ({"rule_version": 2}, "rule_version_changed"),
        ({"details": {"header": "server", "value": "nginx/1.27"}}, "details_changed"),
    ],
)
def test_still_open_with_reasons(change: dict[str, Any], reason: str) -> None:
    b = finding(details={"header": "server", "value": "nginx/1.25"})
    r = one([b], [replace(b, **change)])
    assert r.state is State.STILL_OPEN
    assert reason in r.reasons


def test_present_again_after_false_positive_is_flagged_not_hidden() -> None:
    r = one([finding(triage_status="false_positive")], [finding()])
    assert r.state is State.UNCHANGED
    assert r.reasons == ("baseline_false_positive",)


# --- absent from the current scan -------------------------------------------------------


def test_fixed_requires_coverage_evidence() -> None:
    r = one([finding()], [])
    assert (r.state, r.reasons) == (State.FIXED, ("examined_condition_absent",))
    assert r.coverage_evidence == ("ev-1", "ev-2")


def test_absence_alone_is_never_fixed() -> None:
    assert one([finding()], [], coverage={}).state is State.NOT_RETESTED
    # Covered without any stored response to cite (e.g. TLS failure events).
    r = one([finding()], [], coverage={("SV-HDR-002", ORIGIN, ""): ()})
    assert (r.state, r.reasons) == (State.NOT_RETESTED, ("subject_not_observed",))


def test_not_retested_reports_scan_limitations() -> None:
    r = one(
        [finding()],
        [],
        coverage={},
        coverage_notes=frozenset({"partial_scan", "tls_trust_not_evaluated"}),
    )
    assert r.reasons == ("partial_scan", "subject_not_observed", "tls_trust_not_evaluated")


def test_out_of_scope_is_not_retested() -> None:
    r = one([finding()], [], out_of_scope=frozenset({"a" * 64}))
    assert (r.state, r.reasons) == (State.NOT_RETESTED, ("out_of_scope",))


@pytest.mark.parametrize(
    ("kw", "reason"),
    [
        ({"evaluated_rules": None}, "rule_not_evaluated"),
        ({"evaluated_rules": {"SV-INF-001": 1}}, "rule_not_evaluated"),
        ({"rule_errors": frozenset({"SV-HDR-002"})}, "rule_error"),
        ({"evaluated_rules": {**RULES, "SV-HDR-002": 2}}, "rule_version_changed"),
        ({"coverage_rules": {}}, "coverage_unavailable"),
        ({"coverage_rules": {"SV-HDR-002": 2}}, "coverage_unavailable"),
    ],
)
def test_not_comparable(kw: dict[str, Any], reason: str) -> None:
    r = one([finding()], [], **kw)
    assert (r.state, r.reasons) == (State.NOT_COMPARABLE, (reason,))
    assert r.coverage_evidence == ()


def test_false_positive_that_disappears_is_dismissed_never_fixed() -> None:
    fp = finding(triage_status="false_positive")
    covered = one([fp], [])
    assert covered.state is State.DISMISSED
    assert covered.reasons == ("baseline_false_positive", "examined_condition_absent")
    uncovered = one([fp], [], coverage={})
    assert uncovered.state is State.DISMISSED
    assert uncovered.reasons == ("baseline_false_positive", "subject_not_observed")
    for kw in ({"evaluated_rules": None}, {"evaluated_rules": {**RULES, "SV-HDR-002": 2}}):
        assert one([fp], [], **kw).state is State.DISMISSED


def test_accepted_risk_and_confirmed_can_be_fixed() -> None:
    for status in ("accepted_risk", "confirmed"):
        assert one([finding(triage_status=status)], []).state is State.FIXED


def test_coverage_evidence_is_capped() -> None:
    many = tuple(f"ev-{i:03d}" for i in range(40))
    r = one([finding()], [], coverage={("SV-HDR-002", ORIGIN, ""): many})
    assert r.coverage_evidence == many[:MAX_COVERAGE_EVIDENCE]


def test_moved_endpoint_is_two_identities_not_linked() -> None:
    old = finding(
        "b" * 64, rule_id="SV-INF-002", subject_type="endpoint", subject_key=f"GET {ORIGIN}/login"
    )
    new = finding("c" * 64, rule_id="SV-INF-002", subject_type="endpoint",
                  subject_key=f"GET {ORIGIN}/signin")  # fmt: skip
    records = classify(
        [old], [new], run(coverage={("SV-INF-002", f"GET {ORIGIN}/signin", ""): ("ev-9",)}), {}
    )
    assert [(r.fingerprint[:1], r.state) for r in records] == [
        ("b", State.NOT_RETESTED),
        ("c", State.NEW),
    ]


# --- whole-function properties ------------------------------------------------------------


def _random_case(seed: int) -> tuple[list[FindingSnapshot], list[FindingSnapshot], CurrentRun]:
    rng = random.Random(seed)  # noqa: S311  # test input generation
    rules = ["SV-HDR-002", "SV-INF-001", "SV-INF-002"]
    pool = [f"{i:064x}" for i in range(30)]
    statuses = ["open", "confirmed", "false_positive", "accepted_risk"]
    baseline, current, cov = [], [], {}
    for fp in pool:
        rule = rng.choice(rules)
        base = finding(fp, rule_id=rule, subject_key=f"{ORIGIN}/{fp[-2:]}",
                       triage_status=rng.choice(statuses))  # fmt: skip
        if rng.random() < 0.6:
            baseline.append(base)
        if rng.random() < 0.6:
            current.append(replace(base, severity=rng.choice(["low", "informational"])))
        if rng.random() < 0.5:
            cov[base.coverage_key] = (f"ev-{fp[-3:]}",)
    return baseline, current, run(coverage=cov, rule_errors=frozenset({rng.choice(rules)}))


@pytest.mark.parametrize("seed", range(50))
def test_classification_is_deterministic_and_order_independent(seed: int) -> None:
    baseline, current, current_run = _random_case(seed)
    history = {f"{i:064x}": State.FIXED for i in range(0, 30, 3)}
    expected = classify(baseline, current, current_run, history)
    rng = random.Random(seed)  # noqa: S311  # test shuffling
    for _ in range(3):
        shuffled = classify(
            rng.sample(baseline, len(baseline)), rng.sample(current, len(current)),
            current_run, dict(rng.sample(list(history.items()), len(history))),
        )  # fmt: skip
        assert shuffled == expected
    assert [r.fingerprint for r in expected] == sorted(r.fingerprint for r in expected)


@pytest.mark.parametrize("seed", range(50))
def test_invariants_hold_for_every_record(seed: int) -> None:
    baseline, current, current_run = _random_case(seed)
    records = classify(baseline, current, current_run, {})
    fps = {f.fingerprint for f in baseline} | {f.fingerprint for f in current}
    assert {r.fingerprint for r in records} == fps
    for r in records:
        assert set(r.reasons) <= REASONS
        if r.state is State.FIXED:
            assert r.baseline is not None and r.current is None
            assert r.baseline.triage_status != "false_positive"
            assert r.coverage_evidence
            assert r.baseline.rule_id not in current_run.rule_errors
        if r.baseline is not None and r.baseline.triage_status == "false_positive":
            assert r.state is not State.FIXED
        if r.state in (State.NEW, State.REOPENED):
            assert r.baseline is None and r.current is not None
        if r.state in (State.UNCHANGED, State.STILL_OPEN):
            assert r.baseline is not None and r.current is not None
    assert sum(summarize(records).values()) == len(records)


def test_duplicate_fingerprints_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        classify([finding(), finding()], [], run(), {})
