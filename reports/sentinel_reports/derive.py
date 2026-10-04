"""Figures derived from a snapshot. Computed here, once, so every format shows
the same numbers, always from the findings the report actually lists."""

from collections import Counter
from collections.abc import Mapping
from typing import Any

from sentinel_reports.snapshot import SEVERITY_ORDER, STATUS_ORDER

DETECTION_TYPES = ("automated_detection", "manual_verification_required")
CONFIDENCES = ("high", "medium", "low")


def derive(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    instances = [i for issue in snapshot["issues"] for i in issue["instances"]]
    # False positives stay in the report (appendix) but are not counted as
    # findings of the assessment.
    active = [i for i in instances if i["status"] != "false_positive"]
    severities = Counter(i["severity"] for i in active)
    statuses = Counter(i["status"] for i in instances)
    return {
        "totals": {
            "findings": len(instances),
            "active_findings": len(active),
            "false_positives": statuses["false_positive"],
            "issues": sum(
                1
                for issue in snapshot["issues"]
                if any(i["status"] != "false_positive" for i in issue["instances"])
            ),
            "open_requiring_verification": sum(
                1
                for i in active
                if i["status"] == "open" and i["detection_type"] == "manual_verification_required"
            ),
            "evidence_referenced": len(snapshot["evidence"]),
        },
        "highest_active_severity": next((s for s in SEVERITY_ORDER if severities[s]), None),
        "by_severity": {s: severities[s] for s in SEVERITY_ORDER},
        "by_status": {s: statuses[s] for s in STATUS_ORDER},
        "by_detection_type": {
            d: sum(1 for i in active if i["detection_type"] == d) for d in DETECTION_TYPES
        },
        "by_confidence": {c: sum(1 for i in active if i["confidence"] == c) for c in CONFIDENCES},
    }
