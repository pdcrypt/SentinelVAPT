"""The retest report snapshot (sentinelvapt.retest-report/1): structure and
consistency checks.

The JSON Schema file is the single definition of the structure. The backend
validates a snapshot before storing it and the renderer validates it again
before rendering. The consistency checks below enforce what a schema cannot:
canonical order, that summary counts and record digests match the records,
that every comparison state agrees with the findings present, that FIXED is
backed by current-scan coverage evidence, and that every evidence entry is
cited, bound to the right scan role and unaltered (entry_sha256).
"""

import json
from collections.abc import Callable, Mapping, Sequence
from functools import cache
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator

from sentinel_reports.canonical import canonical_json, sha256_hex
from sentinel_reports.errors import SnapshotInvalid
from sentinel_reports.snapshot import SEVERITY_ORDER

RETEST_SCHEMA_VERSION = "sentinelvapt.retest-report/1"
STATES = (
    "new",
    "reopened",
    "still_open",
    "unchanged",
    "fixed",
    "dismissed",
    "not_retested",
    "not_comparable",
)
PRESENT_STATES = frozenset({"new", "reopened", "still_open", "unchanged"})
ONLY_CURRENT = frozenset({"new", "reopened"})
BOTH = frozenset({"still_open", "unchanged"})
ONLY_BASELINE = frozenset({"fixed", "dismissed", "not_retested", "not_comparable"})
COVERAGE_STATES = frozenset({"fixed", "dismissed"})
ROLES = ("baseline", "current")

# Identity and request time: left out of the content digest.
TIME_DEPENDENT_DOCUMENT_FIELDS = ("report_id", "number", "created_at")


@cache
def retest_snapshot_schema() -> dict[str, Any]:
    source = resources.files("sentinel_reports").joinpath(
        "schema/retest-report-snapshot.schema.json"
    )
    schema: dict[str, Any] = json.loads(source.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


@cache
def _validator() -> Draft202012Validator:
    return Draft202012Validator(retest_snapshot_schema())


def evidence_entry_sha256(entry: Mapping[str, Any]) -> str:
    """Digest of one frozen evidence entry (every field but the digest itself)."""
    return sha256_hex(canonical_json({k: v for k, v in entry.items() if k != "entry_sha256"}))


def records_sha256(records: Sequence[Mapping[str, Any]]) -> str:
    return sha256_hex(canonical_json(list(records)))


def retest_snapshot_digest(snapshot: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json(snapshot))


def retest_content_digest(snapshot: Mapping[str, Any]) -> str:
    document = {
        k: v for k, v in snapshot["document"].items() if k not in TIME_DEPENDENT_DOCUMENT_FIELDS
    }
    return sha256_hex(canonical_json({**snapshot, "document": document}))


def validate_retest_snapshot(snapshot: Mapping[str, Any]) -> None:
    """Raise SnapshotInvalid unless the snapshot matches the schema and is
    internally consistent. Errors name a location or rule, never a value."""
    error = next(iter(_validator().iter_errors(snapshot)), None)
    if error is not None:
        location = "/" + "/".join(str(p) for p in error.absolute_path)
        raise SnapshotInvalid(f"schema violation at {location}")
    _check(snapshot)


def _require_sorted(items: Sequence[Any], key: Callable[[Any], Any], where: str) -> None:
    keys = [key(item) for item in items]
    if keys != sorted(keys):
        raise SnapshotInvalid(f"{where} not in canonical order")


def evidence_sort_key(entry: Mapping[str, Any]) -> tuple[int, str, str, str]:
    return (ROLES.index(entry["role"]), entry["url"], entry["method"], entry["id"])


def _check(s: Mapping[str, Any]) -> None:
    records = s["records"]
    _require_sorted(records, lambda r: r["fingerprint"], "records")
    if len({r["fingerprint"] for r in records}) != len(records):
        raise SnapshotInvalid("records: duplicate fingerprint")

    counts = {state: 0 for state in STATES}
    for record in records:
        counts[record["state"]] += 1
    if counts != dict(s["comparison"]["summary"]):
        raise SnapshotInvalid("comparison summary does not match the records")
    if records_sha256(records) != s["comparison"]["records_sha256"]:
        raise SnapshotInvalid("records digest does not match")

    evidence = s["evidence"]
    _require_sorted(evidence, evidence_sort_key, "evidence")
    by_role: dict[str, set[str]] = {role: set() for role in ROLES}
    scan_of_role = {
        "baseline": s["engagement"]["baseline"]["scan"]["id"],
        "current": s["engagement"]["retest"]["scan"]["id"],
    }
    for entry in evidence:
        if entry["id"] in by_role[entry["role"]]:
            raise SnapshotInvalid("evidence: duplicate (role, id)")
        if entry["scan_id"] != scan_of_role[entry["role"]]:
            raise SnapshotInvalid("evidence bound to the wrong scan")
        if evidence_entry_sha256(entry) != entry["entry_sha256"]:
            raise SnapshotInvalid("evidence entry digest does not match")
        by_role[entry["role"]].add(entry["id"])

    cited: dict[str, set[str]] = {role: set() for role in ROLES}
    rules = s["rules"]
    for record in records:
        state, base, cur = record["state"], record["baseline"], record["current"]
        if state in ONLY_CURRENT and not (base is None and cur is not None):
            raise SnapshotInvalid("state requires only a current finding")
        if state in BOTH and (base is None or cur is None):
            raise SnapshotInvalid("state requires both findings")
        if state in ONLY_BASELINE and not (base is not None and cur is None):
            raise SnapshotInvalid("state requires only a baseline finding")
        compared = record["triage_when_compared"]
        reported = record["triage_when_reported"]
        for pair in (compared, reported):
            if (pair["baseline"] is None) != (base is None) or (pair["current"] is None) != (
                cur is None
            ):
                raise SnapshotInvalid("triage must be present exactly for present findings")
        if state == "fixed" and compared["baseline"] == "false_positive":
            raise SnapshotInvalid("a false positive is never fixed")
        if state == "dismissed" and compared["baseline"] != "false_positive":
            raise SnapshotInvalid("dismissed requires a baseline false positive")
        coverage = record["coverage_evidence_ids"]
        if state == "fixed" and not coverage:
            raise SnapshotInvalid("a fixed record requires coverage evidence")
        if coverage and state not in COVERAGE_STATES:
            raise SnapshotInvalid("coverage evidence on a record that is not fixed or dismissed")
        if state == "reopened" and (
            record["history"] is None or record["history"]["state"] != "fixed"
        ):
            raise SnapshotInvalid("reopened requires an earlier fixed record in the chain")
        if (record["history"] is not None) and state not in ONLY_CURRENT:
            raise SnapshotInvalid("history is only recorded for new or reopened records")
        cited["current"].update(coverage)
        for role, view in (("baseline", base), ("current", cur)):
            if view is None:
                continue
            if f"{record['rule_id']}@{view['rule_version']}" not in rules:
                raise SnapshotInvalid("rule metadata missing for a finding's rule version")
            cited[role].update(view["evidence_ids"])
    for key, rule in rules.items():
        if key != f"{rule['id']}@{rule['version']}":
            raise SnapshotInvalid("rules: key does not match its rule")
    if cited != by_role:
        raise SnapshotInvalid("evidence does not match the records' references")

    lineage = s["lineage"]
    if [entry["position"] for entry in lineage] != list(range(len(lineage))):
        raise SnapshotInvalid("lineage positions are not consecutive")
    if lineage[-1]["assessment"]["id"] != s["engagement"]["retest"]["assessment"]["id"]:
        raise SnapshotInvalid("lineage does not end with the retest assessment")
    if (
        lineage[-1]["comparison"] is None
        or lineage[-1]["comparison"]["id"] != s["comparison"]["id"]
    ):
        raise SnapshotInvalid("lineage does not end with the reported comparison")


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)
