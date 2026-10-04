"""The report snapshot: structure (JSON Schema) and consistency checks.

The schema file is the single definition of the snapshot's structure. The
backend validates a snapshot before storing it and the renderer validates it
again before rendering, so a malformed or altered snapshot never renders.
"""

import json
from collections.abc import Callable, Mapping, Sequence
from functools import cache
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator

from sentinel_reports.canonical import canonical_json, sha256_hex
from sentinel_reports.errors import SnapshotInvalid

SCHEMA_VERSION = "sentinelvapt.report/1"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
STATUS_ORDER = ("open", "confirmed", "accepted_risk", "false_positive")
BODY_SHA256_LABEL = "SHA-256 of the unredacted captured response bytes."

# Fields of `document` that identify one report or the moment it was requested.
# They are left out of the content digest, so two reports of the same data
# with the same inputs have the same content digest.
TIME_DEPENDENT_DOCUMENT_FIELDS = ("report_id", "number", "created_at")


@cache
def snapshot_schema() -> dict[str, Any]:
    source = resources.files("sentinel_reports").joinpath("schema/report-snapshot.schema.json")
    schema: dict[str, Any] = json.loads(source.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


@cache
def _validator() -> Draft202012Validator:
    return Draft202012Validator(snapshot_schema())


def validate_snapshot(snapshot: Mapping[str, Any]) -> None:
    """Raise SnapshotInvalid unless the snapshot matches the schema and is
    internally consistent. The error names a location, never a value."""
    error = next(iter(_validator().iter_errors(snapshot)), None)
    if error is not None:
        location = "/" + "/".join(str(p) for p in error.absolute_path)
        raise SnapshotInvalid(f"schema violation at {location}")
    _check_consistency(snapshot)


def _require_sorted(items: Sequence[Any], key: Callable[[Any], Any], where: str) -> None:
    keys = [key(item) for item in items]
    if keys != sorted(keys):
        raise SnapshotInvalid(f"{where} not in canonical order")


def _check_consistency(s: Mapping[str, Any]) -> None:
    rank = {severity: i for i, severity in enumerate(SEVERITY_ORDER)}
    issues = s["issues"]
    _require_sorted(issues, lambda i: (rank[i["rule"]["severity"]], i["rule"]["id"]), "issues")
    if len({i["rule"]["id"] for i in issues}) != len(issues):
        raise SnapshotInvalid("issues: duplicate rule")

    evidence_ids = [e["id"] for e in s["evidence"]]
    if len(set(evidence_ids)) != len(evidence_ids):
        raise SnapshotInvalid("evidence: duplicate id")
    _require_sorted(s["evidence"], lambda e: (e["url"], e["method"], e["id"]), "evidence")

    referenced: set[str] = set()
    finding_ids: set[str] = set()
    fingerprints: set[str] = set()
    for issue in issues:
        instances = issue["instances"]
        _require_sorted(
            instances,
            lambda i: (i["subject_key"], i["discriminator"], i["fingerprint"]),
            "issue instances",
        )
        for instance in instances:
            if instance["subject_type"] != issue["rule"]["subject_type"]:
                raise SnapshotInvalid("instance subject type differs from its rule")
            if instance["finding_id"] in finding_ids or instance["fingerprint"] in fingerprints:
                raise SnapshotInvalid("duplicate finding")
            finding_ids.add(instance["finding_id"])
            fingerprints.add(instance["fingerprint"])
            referenced.update(instance["evidence_ids"])
    if referenced != set(evidence_ids):
        # Every cited record is present, and nothing uncited is included: the
        # snapshot carries only evidence that its findings reference.
        raise SnapshotInvalid("evidence does not match the findings' references")

    _require_sorted(s["methodology"]["rules"], lambda r: r["id"], "methodology rules")
    _require_sorted(
        s["timeline"]["entries"], lambda e: (e["at"], e["kind"], e["detail"]), "timeline"
    )


def snapshot_digest(snapshot: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json(snapshot))


def content_digest(snapshot: Mapping[str, Any]) -> str:
    """Digest of the report's content without its identity and request time."""
    document = {
        k: v for k, v in snapshot["document"].items() if k not in TIME_DEPENDENT_DOCUMENT_FIELDS
    }
    return sha256_hex(canonical_json({**snapshot, "document": document}))
