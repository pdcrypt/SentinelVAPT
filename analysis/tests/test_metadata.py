"""Rule metadata: completeness, classification constraints, versioning discipline
and the generated catalog."""

import re
from pathlib import Path

import pytest
from sentinel_analysis.catalog import current_lock_entries, read_lockfile, render_markdown
from sentinel_analysis.model import Confidence, DetectionType, Severity, SubjectType
from sentinel_analysis.rules import REGISTRY

RULES = {rule.meta.id: rule.meta for rule in REGISTRY}
DOCS = Path(__file__).resolve().parents[2] / "docs" / "rules.md"

EXPECTED_RULES = {
    # id: (severity, confidence, detection type, subject)
    "SV-TRN-001": ("low", "high", "automated_detection", "origin"),
    "SV-TRN-002": ("low", "high", "manual_verification_required", "origin"),
    "SV-HDR-001": ("low", "high", "automated_detection", "origin"),
    "SV-HDR-002": ("low", "high", "automated_detection", "origin"),
    "SV-HDR-003": ("low", "high", "automated_detection", "origin"),
    "SV-HDR-004": ("informational", "high", "automated_detection", "origin"),
    "SV-CKE-001": ("low", "medium", "manual_verification_required", "origin"),
    "SV-CKE-002": ("low", "high", "automated_detection", "origin"),
    "SV-CKE-003": ("informational", "high", "automated_detection", "origin"),
    "SV-INF-001": ("informational", "high", "automated_detection", "origin"),
    "SV-INF-002": ("low", "medium", "manual_verification_required", "endpoint"),
    "SV-INF-003": ("low", "medium", "automated_detection", "endpoint"),
    "SV-COR-001": ("informational", "high", "manual_verification_required", "origin"),
    "SV-MTH-001": ("low", "low", "manual_verification_required", "endpoint"),
}


def test_exactly_the_approved_fourteen_rules() -> None:
    assert set(RULES) == set(EXPECTED_RULES)
    assert len(REGISTRY) == 14
    assert [r.meta.id for r in REGISTRY] == sorted(RULES)  # deterministic registry order


@pytest.mark.parametrize("rule_id", sorted(EXPECTED_RULES))
def test_classification(rule_id: str) -> None:
    meta = RULES[rule_id]
    assert (
        meta.severity.value,
        meta.confidence.value,
        meta.detection_type.value,
        meta.subject_type.value,
    ) == EXPECTED_RULES[rule_id]


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_metadata_is_complete(rule_id: str) -> None:
    meta = RULES[rule_id]
    assert re.fullmatch(r"SV-[A-Z]{3}-\d{3}", meta.id)
    assert meta.version >= 1
    for text in (meta.title, meta.description, meta.proves, meta.does_not_prove, meta.remediation):
        assert text.strip() and len(text) < 600


def test_no_passive_rule_exceeds_low() -> None:
    allowed = {Severity.LOW, Severity.INFORMATIONAL}
    assert all(meta.severity in allowed for meta in RULES.values())


def test_proves_text_never_claims_exploitability() -> None:
    for meta in RULES.values():
        lowered = meta.proves.lower()
        assert "exploitable" not in lowered and "vulnerable" not in lowered, meta.id


def test_enums_are_the_documented_values() -> None:
    assert {d.value for d in DetectionType} == {
        "automated_detection",
        "manual_verification_required",
    }
    assert [s.value for s in Severity] == ["critical", "high", "medium", "low", "informational"]
    assert {c.value for c in Confidence} == {"high", "medium", "low"}
    assert {s.value for s in SubjectType} == {"origin", "endpoint"}


def test_metadata_changes_require_a_version_bump() -> None:
    """Editing a rule's metadata without bumping its version changes the hash
    for an existing RULE@version key. Run `python -m sentinel_analysis.catalog
    lock` after bumping a version."""
    locked = read_lockfile()
    for key, digest in current_lock_entries().items():
        assert key in locked, f"{key} missing from rule_metadata.lock.json"
        assert locked[key] == digest, f"{key} metadata changed without a version bump"


def test_generated_catalog_is_up_to_date() -> None:
    assert DOCS.read_text(encoding="utf-8") == render_markdown(), (
        "regenerate with: python -m sentinel_analysis.catalog docs > ../docs/rules.md"
    )
