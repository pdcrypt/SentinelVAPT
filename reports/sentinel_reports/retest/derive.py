"""Figures and orderings derived from a retest snapshot.

Presentation only: comparison states are copied from the snapshot and never
reclassified. The two shares are SentinelVAPT-specific, not industry metrics,
and are computed with integer arithmetic so every format shows the same text.
"""

from collections.abc import Mapping
from typing import Any

from sentinel_reports.retest.snapshot import STATES, severity_rank

FALSE_POSITIVE = "false_positive"
UNVERIFIED_STATES = frozenset({"not_retested", "not_comparable"})
COMPARED_ATTRIBUTES = ("rule_version", "severity", "confidence", "detection_type")


def _percent(numerator: int, denominator: int) -> str:
    """numerator / denominator as a percentage with one decimal, rounded half
    up, or "n/a" for a zero denominator."""
    if denominator == 0:
        return "n/a"
    tenths = (numerator * 2000 + denominator) // (2 * denominator)
    return f"{tenths // 10}.{tenths % 10}%"


def _view(record: Mapping[str, Any]) -> Mapping[str, Any]:
    view: Mapping[str, Any] | None = (
        record["current"] if record["current"] is not None else record["baseline"]
    )
    assert view is not None  # noqa: S101  # validated: every record has a finding
    return view


def record_order(record: Mapping[str, Any]) -> tuple[int, str, str, str, str]:
    view = _view(record)
    return (
        severity_rank(view["severity"]),
        record["rule_id"],
        view["subject_key"],
        view["discriminator"],
        record["fingerprint"],
    )


def _is_counter(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def differences(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Baseline -> current differences of a record with both findings, under
    the same rule as comparison policy cmp-1 (integer counters ignored)."""
    base, cur = record["baseline"], record["current"]
    if base is None or cur is None:
        return []
    changes = [
        {"attribute": attr, "baseline": base[attr], "current": cur[attr]}
        for attr in COMPARED_ATTRIBUTES
        if base[attr] != cur[attr]
    ]
    keys = sorted(
        k
        for k in set(base["details"]) | set(cur["details"])
        if not _is_counter(base["details"].get(k)) and not _is_counter(cur["details"].get(k))
    )
    for key in keys:
        old, new = base["details"].get(key), cur["details"].get(key)
        if old != new:
            changes.append({"attribute": f"details.{key}", "baseline": old, "current": new})
    return changes


def _rule_version_rows(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    runs = snapshot["engagement"]
    baseline = runs["baseline"]["run"]["rule_versions"]
    retest = runs["retest"]["run"]["rule_versions"]
    known = baseline is not None and retest is not None
    rows = []
    if known:
        old = {r["rule_id"]: r["version"] for r in baseline}
        new = {r["rule_id"]: r["version"] for r in retest}
        for rule_id in sorted(old.keys() | new.keys()):
            if old.get(rule_id) != new.get(rule_id):
                rows.append(
                    {"rule_id": rule_id, "baseline": old.get(rule_id), "retest": new.get(rule_id)}
                )
    affected = [r for r in snapshot["records"] if "rule_version_changed" in r["reasons"]]
    return {
        "known": known,
        "baseline_known": baseline is not None,
        "retest_known": retest is not None,
        "rows": rows,
        "affected": sorted(affected, key=record_order),
    }


def derive_retest(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    records = snapshot["records"]
    counts = {state: 0 for state in STATES}
    for record in records:
        counts[record["state"]] += 1
    active = [
        r
        for r in records
        if r["baseline"] is not None and r["triage_when_compared"]["baseline"] != FALSE_POSITIVE
    ]
    fixed = sum(1 for r in active if r["state"] == "fixed")
    unverified = sum(1 for r in active if r["state"] in UNVERIFIED_STATES)
    sections = [
        {
            "state": state,
            "records": sorted((r for r in records if r["state"] == state), key=record_order),
        }
        for state in STATES
    ]
    return {
        "total_records": len(records),
        "counts": counts,
        "baseline_active": len(active),
        "metrics": {
            "verified_fixed_share": {
                "numerator": fixed,
                "denominator": len(active),
                "value": _percent(fixed, len(active)),
            },
            "unverified_share": {
                "numerator": unverified,
                "denominator": len(active),
                "value": _percent(unverified, len(active)),
            },
        },
        "sections": sections,
        "differences": {
            r["fingerprint"]: differences(r) for r in records if r["state"] == "still_open"
        },
        "rule_versions": _rule_version_rows(snapshot),
    }
