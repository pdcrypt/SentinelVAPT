"""Mappings use only verified identifiers, and follow the mapping policy."""

import pytest
from sentinel_analysis.rules import REGISTRY
from sentinel_analysis.taxonomy import (
    CWE,
    EXCLUDED_CWES,
    EXCLUDED_WSTG,
    OWASP_TOP10_2025,
    OWASP_TOP10_2025_MAPPED_CWES,
    WSTG_V42,
)

RULES = {rule.meta.id: rule.meta for rule in REGISTRY}

# The approved, verified mappings. Changing one must be a deliberate edit here.
EXPECTED = {
    "SV-TRN-001": (("A04:2025",), ("WSTG-CRYP-03",), (319,)),
    "SV-TRN-002": ((), ("WSTG-CRYP-01",), ()),
    "SV-HDR-001": ((), ("WSTG-CONF-07",), ()),
    "SV-HDR-002": ((), (), ()),
    "SV-HDR-003": ((), ("WSTG-CLNT-09",), (1021,)),
    "SV-HDR-004": ((), (), ()),
    "SV-CKE-001": (("A02:2025",), ("WSTG-SESS-02",), (1004,)),
    "SV-CKE-002": (("A02:2025",), ("WSTG-SESS-02",), (614,)),
    "SV-CKE-003": ((), ("WSTG-SESS-02",), (1275,)),
    "SV-INF-001": ((), ("WSTG-INFO-02",), (497,)),
    "SV-INF-002": (("A10:2025",), ("WSTG-ERRH-01",), (209,)),
    "SV-INF-003": ((), (), (548,)),
    "SV-COR-001": ((), ("WSTG-CLNT-07",), ()),
    "SV-MTH-001": ((), ("WSTG-CONF-06",), ()),
}


@pytest.mark.parametrize("rule_id", sorted(EXPECTED))
def test_mappings_are_exactly_the_verified_ones(rule_id: str) -> None:
    meta = RULES[rule_id]
    assert (meta.owasp_top10, meta.wstg, meta.cwe) == EXPECTED[rule_id]


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_every_identifier_is_in_the_controlled_vocabulary(rule_id: str) -> None:
    meta = RULES[rule_id]
    assert set(meta.owasp_top10) <= set(OWASP_TOP10_2025)
    assert set(meta.wstg) <= set(WSTG_V42)
    assert set(meta.cwe) <= set(CWE)


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_top10_category_is_justified_by_a_mapped_cwe(rule_id: str) -> None:
    """Policy: a Top 10:2025 category only if one of the rule's CWEs is in that
    category's official List of Mapped CWEs."""
    meta = RULES[rule_id]
    for category in meta.owasp_top10:
        assert set(meta.cwe) & OWASP_TOP10_2025_MAPPED_CWES[category], (rule_id, category)


def test_excluded_identifiers_are_never_used() -> None:
    for meta in RULES.values():
        assert not set(meta.cwe) & set(EXCLUDED_CWES)
        assert not set(meta.wstg) & set(EXCLUDED_WSTG)


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_references_point_at_the_mapped_sources(rule_id: str) -> None:
    meta = RULES[rule_id]
    expected = {WSTG_V42[w].source for w in meta.wstg} | {CWE[c].source for c in meta.cwe}
    assert set(meta.references) == expected
    for url in meta.references:
        assert url.startswith(
            ("https://wstg.owasp.org/v4.2/", "https://cwe.mitre.org/data/definitions/")
        )


def test_vocabulary_titles_match_the_verified_sources() -> None:
    assert OWASP_TOP10_2025["A02:2025"] == "Security Misconfiguration"
    assert OWASP_TOP10_2025["A04:2025"] == "Cryptographic Failures"
    assert OWASP_TOP10_2025["A10:2025"] == "Mishandling of Exceptional Conditions"
    assert len(OWASP_TOP10_2025) == 10
    assert WSTG_V42["WSTG-CONF-07"].title == "Test HTTP Strict Transport Security"
    assert WSTG_V42["WSTG-SESS-02"].title == "Testing for Cookies Attributes"
    assert CWE[1004].title == "Sensitive Cookie Without 'HttpOnly' Flag"
    assert CWE[614].title == "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
    assert 693 in EXCLUDED_CWES and 942 in EXCLUDED_CWES
