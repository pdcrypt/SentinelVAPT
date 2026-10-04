"""Engine: determinism, isolation, contract enforcement, bounds, identity."""

import hashlib
import random
from collections.abc import Iterator
from dataclasses import replace

import pytest
from sentinel_analysis import analyze
from sentinel_analysis.context import RuleContext
from sentinel_analysis.engine import (
    COVERAGE_PARTIAL,
    COVERAGE_TLS_NOT_EVALUATED,
    MAX_EVIDENCE_REFS,
    RULESET_VERSION,
    ruleset_version,
)
from sentinel_analysis.fingerprint import fingerprint
from sentinel_analysis.model import Confidence, Match, SubjectType
from sentinel_analysis.rules import REGISTRY, Rule
from sentinel_analysis.rules.headers import HDR_004

from tests.builders import Page, build, cookie


def lab_site() -> list[Page]:
    return [
        Page(
            "http://lab.test/", headers=[("Server", "nginx/1.25.3")], cookies=[cookie("PHPSESSID")]
        ),
        Page("http://lab.test/about", title="About"),
        Page("http://lab.test/err", status=500, body="Traceback (most recent call last):"),
        Page("http://lab.test/files/", title="Index of /files/"),
        Page("http://lab.test/", method="OPTIONS", headers=[("Allow", "GET, PUT, DELETE")]),
    ]


def test_same_observations_give_identical_results() -> None:
    pages = lab_site()
    first, second = analyze(build(pages)), analyze(build(pages))
    assert first == second
    assert first.candidates  # the fixture does produce findings


def test_input_order_does_not_matter() -> None:
    obs = build(lab_site())
    baseline = analyze(obs)
    rng = random.Random(4)  # noqa: S311  # shuffles test input, not cryptographic
    for _ in range(10):
        shuffled = replace(
            obs,
            endpoints=tuple(rng.sample(obs.endpoints, len(obs.endpoints))),
            responses=tuple(rng.sample(obs.responses, len(obs.responses))),
            cookies=tuple(rng.sample(obs.cookies, len(obs.cookies))),
        )
        assert analyze(shuffled) == baseline
        assert analyze(shuffled, rules=tuple(reversed(REGISTRY))) == baseline


def test_candidates_are_sorted_and_unique() -> None:
    candidates = analyze(build(lab_site())).candidates
    keys = [(c.rule_id, c.fingerprint) for c in candidates]
    assert keys == sorted(keys)
    assert len({c.fingerprint for c in candidates}) == len(candidates)


def test_fingerprint_formula_and_what_it_excludes() -> None:
    expected = hashlib.sha256(b"v1|SV-HDR-004|origin|http://lab.test:80|").hexdigest()
    assert fingerprint("SV-HDR-004", SubjectType.ORIGIN, "http://lab.test:80", "") == expected
    [candidate] = [c for c in analyze(build(lab_site())).candidates if c.rule_id == "SV-HDR-004"]
    assert candidate.fingerprint == expected
    # A new rule version, another scan, other evidence: same identity.
    bumped = Rule(replace(HDR_004.meta, version=2), HDR_004.evaluate)
    other_scan = build([Page("http://lab.test/x"), Page("http://lab.test/y")])
    [again] = analyze(other_scan, rules=[bumped]).candidates
    assert again.fingerprint == expected and again.rule_version == 2


def _rule(evaluate, rule_id: str = "SV-TST-001") -> Rule:  # type: ignore[no-untyped-def]
    return Rule(replace(HDR_004.meta, id=rule_id), evaluate)


def test_a_failing_rule_is_isolated_and_its_message_is_not_kept() -> None:
    def boom(ctx: RuleContext) -> Iterator[Match]:
        raise RuntimeError("secret from target: PHPSESSID=abc")

    result = analyze(build(lab_site()), rules=[*REGISTRY, _rule(boom, "SV-ZZZ-999")])
    assert [(e.rule_id, e.error) for e in result.rule_errors] == [("SV-ZZZ-999", "RuntimeError")]
    assert "abc" not in repr(result)
    assert len(result.candidates) == len(analyze(build(lab_site())).candidates)


@pytest.mark.parametrize(
    "bad_match",
    [
        Match(subject_key=""),
        Match(subject_key="x" * 3000),
        Match(subject_key="o", discriminator="d" * 300),
        Match(subject_key="o", evidence_ids=("not-in-this-scan",)),
        Match(subject_key="o", details={"k": 1.5}),  # type: ignore[dict-item]
        Match(subject_key="o", details={f"k{i}": i for i in range(11)}),
        Match(subject_key="o", details={"": 1}),
        Match(subject_key="o", affected_count=0),
        Match(subject_key="o", confidence=Confidence.HIGH),  # cannot raise above meta
    ],
)
def test_contract_violations_drop_the_rule(bad_match: Match) -> None:
    meta_low = replace(HDR_004.meta, id="SV-TST-001", confidence=Confidence.MEDIUM)
    rule = Rule(meta_low, lambda ctx: iter([bad_match]))
    result = analyze(build(lab_site()), rules=[rule])
    assert result.candidates == ()
    assert result.rule_errors[0].rule_id == "SV-TST-001"


def test_too_many_matches_is_a_contract_violation() -> None:
    rule = _rule(lambda ctx: (Match(subject_key=f"s{i}") for i in range(10_000)))
    result = analyze(build(lab_site()), rules=[rule])
    assert result.candidates == () and result.rule_errors[0].error == "RuleContractError"


def test_lowering_confidence_is_allowed_and_details_are_bounded() -> None:
    rule = _rule(
        lambda ctx: iter(
            [Match(subject_key="o", confidence=Confidence.LOW, details={"v": "x" * 1000})]
        )
    )
    [candidate] = analyze(build(lab_site()), rules=[rule]).candidates
    assert candidate.confidence is Confidence.LOW
    assert len(str(candidate.details["v"])) == 300


def test_duplicate_fingerprints_merge_deterministically() -> None:
    pages = [Page(f"http://lab.test/p{i}") for i in range(40)]
    obs = build(pages)
    ids = sorted(r.evidence_id for r in obs.responses)
    rule = _rule(
        lambda ctx: iter(
            [
                Match(subject_key="o", evidence_ids=tuple(ids[:30]), affected_count=30),
                Match(
                    subject_key="o",
                    evidence_ids=tuple(ids[20:]),
                    affected_count=10,
                    confidence=Confidence.LOW,
                ),
            ]
        )
    )
    [merged] = analyze(obs, rules=[rule]).candidates
    assert merged.affected_count == 40
    assert merged.confidence is Confidence.LOW
    assert merged.evidence_ids == tuple(ids[:MAX_EVIDENCE_REFS])  # capped, sorted


def test_coverage_notes() -> None:
    assert analyze(build(lab_site())).coverage_notes == ()
    assert analyze(build(lab_site(), stop_reason="request_limit")).coverage_notes == (
        COVERAGE_PARTIAL,
    )
    assert (
        COVERAGE_TLS_NOT_EVALUATED
        in analyze(build(lab_site(), allow_untrusted_tls=True)).coverage_notes
    )


def test_ruleset_version_tracks_rule_versions_and_metadata() -> None:
    assert ruleset_version() == RULESET_VERSION
    bumped = [
        r if r.meta.id != "SV-HDR-004" else Rule(replace(r.meta, version=2), r.evaluate)
        for r in REGISTRY
    ]
    edited = [
        r if r.meta.id != "SV-HDR-004" else Rule(replace(r.meta, title="x"), r.evaluate)
        for r in REGISTRY
    ]
    assert len({ruleset_version(), ruleset_version(bumped), ruleset_version(edited)}) == 3


def test_empty_scan() -> None:
    result = analyze(build([]))
    assert result.candidates == () and result.rule_errors == ()
    assert len(result.rules_evaluated) == 14
