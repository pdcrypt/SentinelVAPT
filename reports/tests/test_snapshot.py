import copy
from typing import Any

import pytest

from sentinel_reports import (
    SnapshotInvalid,
    content_digest,
    derive,
    snapshot_digest,
    validate_snapshot,
)
from sentinel_reports.snapshot import snapshot_schema
from tests.factory import evidence, snapshot, uid


def test_factory_snapshot_is_valid() -> None:
    validate_snapshot(snapshot())


def test_schema_is_a_valid_2020_12_schema_with_no_remote_references() -> None:
    schema = snapshot_schema()
    text = str(schema)
    assert schema["$id"].startswith("urn:")
    # The only absolute URL is the meta-schema identifier, which jsonschema
    # resolves from its bundled copy; no $ref points outside the document.
    assert all(ref.startswith("#/") for ref in _refs(schema))
    assert "http://" not in text


def _refs(node: Any) -> list[str]:
    if isinstance(node, dict):
        found = [node["$ref"]] if "$ref" in node else []
        return found + [r for v in node.values() for r in _refs(v)]
    if isinstance(node, list):
        return [r for v in node for r in _refs(v)]
    return []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.update(extra=1),
        lambda s: s["document"].update(kind="published"),
        lambda s: s["document"].update(number="R-1"),
        lambda s: s["document"].update(created_at="2026-10-04 12:00"),
        lambda s: s["document"].update(created_at="2026-10-04T12:00:00+02:00"),
        lambda s: s["document"]["template"].update(id="../etc"),
        lambda s: s["scan"].update(status="failed"),
        lambda s: s["evidence"][0].update(body_sha256_label="hash"),
        lambda s: s["evidence"][0].update(excerpt="x" * 1025),
        lambda s: s["evidence"][0].update(raw_body="secret"),
        lambda s: s["issues"][0]["instances"][0].update(evidence_ids=[uid(1)] * 2),
        lambda s: s["issues"][0]["instances"][0]["details"].update(nested={"a": 1}),
        lambda s: s["issues"][0]["rule"].update(references=["http://cwe.mitre.org/x"]),
        lambda s: s["issues"][0]["rule"]["wstg"][0].update(url="javascript:alert(1)"),
        lambda s: s["issues"][0]["instances"][0].update(status="fixed"),
        lambda s: s["inputs"].update(executive_summary_note="x" * 4001),
    ],
)
def test_schema_rejects_malformed_snapshots(mutate: Any) -> None:
    s = snapshot()
    mutate(s)
    with pytest.raises(SnapshotInvalid):
        validate_snapshot(s)


def test_schema_errors_name_a_location_not_a_value() -> None:
    s = snapshot()
    s["evidence"][0]["excerpt"] = "TOP-SECRET-VALUE" * 100
    with pytest.raises(SnapshotInvalid) as info:
        validate_snapshot(s)
    assert "TOP-SECRET-VALUE" not in str(info.value)
    assert "/evidence/0/excerpt" in str(info.value)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda s: s["issues"].reverse(), "issues"),
        (lambda s: s["evidence"].reverse(), "evidence"),
        (lambda s: s["issues"][1]["instances"].reverse(), "instances"),
        (lambda s: s["methodology"]["rules"].reverse(), "methodology"),
        (lambda s: s["timeline"]["entries"].reverse(), "timeline"),
        (lambda s: s["evidence"].append(evidence(9)), "references"),
        (lambda s: s["evidence"].pop(), "references"),
        (lambda s: s["issues"][1]["instances"][0].update(subject_type="endpoint"), "subject"),
        (
            lambda s: s["issues"][1]["instances"][1].update(
                finding_id=s["issues"][1]["instances"][0]["finding_id"]
            ),
            "duplicate",
        ),
        (lambda s: s["issues"][1]["rule"].update(id="SV-HDR-002", severity="low"), "duplicate"),
    ],
)
def test_consistency_checks(mutate: Any, message: str) -> None:
    s = snapshot()
    mutate(s)
    with pytest.raises(SnapshotInvalid, match=message):
        validate_snapshot(s)


def test_digests() -> None:
    a, b = snapshot(), snapshot()
    assert snapshot_digest(a) == snapshot_digest(b)
    b["document"].update(
        report_id=uid(99), number="SV-R-000099", created_at="2027-01-01T00:00:00+00:00"
    )
    assert snapshot_digest(a) != snapshot_digest(b)
    assert content_digest(a) == content_digest(b)  # identity and request time only
    c = copy.deepcopy(a)
    c["issues"][0]["instances"][0]["status"] = "confirmed"
    assert content_digest(a) != content_digest(c)


def test_derived_figures_exclude_false_positives() -> None:
    d = derive(snapshot())
    assert d["totals"] == {
        "findings": 3,
        "active_findings": 2,
        "false_positives": 1,
        "issues": 2,
        "open_requiring_verification": 0,
        "evidence_referenced": 2,
    }
    assert d["by_severity"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 1,
        "informational": 1,
    }
    assert d["highest_active_severity"] == "low"
    assert d["by_status"] == {"open": 2, "confirmed": 0, "accepted_risk": 0, "false_positive": 1}


def test_open_manual_findings_are_counted_as_requiring_verification() -> None:
    s = snapshot()
    s["issues"][0]["instances"][0]["detection_type"] = "manual_verification_required"
    assert derive(s)["totals"]["open_requiring_verification"] == 1
    s["issues"][0]["instances"][0]["status"] = "confirmed"
    assert derive(s)["totals"]["open_requiring_verification"] == 0
