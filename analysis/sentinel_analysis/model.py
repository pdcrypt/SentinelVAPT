"""Core types of the rule engine.

Three separate questions, three separate fields (ADR 0009):
- severity:       how bad it would be if true (project-defined scale, not CVSS)
- confidence:     how sure the observed condition holds, given the evidence
- detection type: whether the observation alone establishes the issue, or a
                  human must verify it
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Project-defined. critical/high/medium are reserved for evidence that by
    itself shows exposure or compromise; no Phase 4 passive rule uses them."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}


class Confidence(StrEnum):
    HIGH = "high"  # the condition was directly observed
    MEDIUM = "medium"  # observed through a documented heuristic
    LOW = "low"  # weak signal

    @property
    def rank(self) -> int:
        return {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}[self]


class DetectionType(StrEnum):
    # The observation alone establishes the stated configuration issue.
    AUTOMATED_DETECTION = "automated_detection"
    # An indicator: impact, sensitivity or exploitability needs a human.
    MANUAL_VERIFICATION_REQUIRED = "manual_verification_required"


class Category(StrEnum):
    TRANSPORT = "transport"
    HEADERS = "headers"
    COOKIES = "cookies"
    DISCLOSURE = "disclosure"
    CORS = "cors"
    HTTP_METHODS = "http_methods"


class SubjectType(StrEnum):
    ORIGIN = "origin"  # subject_key: "scheme://host:port"
    ENDPOINT = "endpoint"  # subject_key: "METHOD url"


DetailValue = str | int | bool | None


@dataclass(frozen=True)
class RuleMeta:
    id: str
    version: int
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    detection_type: DetectionType
    subject_type: SubjectType
    description: str
    proves: str
    does_not_prove: str
    remediation: str
    owasp_top10: tuple[str, ...] = ()
    wstg: tuple[str, ...] = ()
    cwe: tuple[int, ...] = ()
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "detection_type": self.detection_type.value,
            "subject_type": self.subject_type.value,
            "description": self.description,
            "proves": self.proves,
            "does_not_prove": self.does_not_prove,
            "remediation": self.remediation,
            "owasp_top10": list(self.owasp_top10),
            "wstg": list(self.wstg),
            "cwe": list(self.cwe),
            "references": list(self.references),
        }

    def metadata_hash(self) -> str:
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class Match:
    """One thing a rule observed. Identity comes from subject_key + discriminator."""

    subject_key: str
    discriminator: str = ""
    evidence_ids: tuple[str, ...] = ()
    details: Mapping[str, DetailValue] = field(default_factory=dict)
    affected_count: int = 1
    confidence: Confidence | None = None  # may only lower the rule's confidence
    origin: str | None = None  # "scheme://host:port", to link the finding to an asset
    endpoint_id: str | None = None  # for endpoint subjects


@dataclass(frozen=True)
class FindingCandidate:
    rule_id: str
    rule_version: int
    fingerprint: str
    category: Category
    subject_type: SubjectType
    subject_key: str
    discriminator: str
    severity: Severity
    confidence: Confidence
    detection_type: DetectionType
    evidence_ids: tuple[str, ...]
    details: Mapping[str, DetailValue]
    affected_count: int
    origin: str | None
    endpoint_id: str | None


@dataclass(frozen=True)
class RuleError:
    """A rule that raised or broke its contract. Only the exception type is
    kept: exception text may contain target data."""

    rule_id: str
    error: str


@dataclass(frozen=True)
class AnalysisResult:
    ruleset_version: str
    candidates: tuple[FindingCandidate, ...]
    rule_errors: tuple[RuleError, ...]
    rules_evaluated: tuple[str, ...]
    coverage_notes: tuple[str, ...]
