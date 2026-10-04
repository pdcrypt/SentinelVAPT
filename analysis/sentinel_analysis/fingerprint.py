"""Finding identity.

fingerprint = sha256("v1|" + rule_id + "|" + subject_type + "|" + subject_key
                     + "|" + discriminator)

Deliberately excludes scan id, analysis run id, rule version, severity,
confidence, evidence ids and timestamps, so the same issue on the same subject
keeps the same identity across scans and rule versions (ADR 0009). A rule
whose *meaning* changes must get a new rule id, not a new version.
"""

import hashlib

from sentinel_analysis.model import SubjectType


def fingerprint(
    rule_id: str, subject_type: SubjectType, subject_key: str, discriminator: str
) -> str:
    material = f"v1|{rule_id}|{subject_type.value}|{subject_key}|{discriminator}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
