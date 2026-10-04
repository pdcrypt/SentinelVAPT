"""SentinelVAPT deterministic analysis.

Turns a scan's persisted, redacted observations into explainable finding
candidates. Offline and deterministic: no network, no database, no AI. The
backend builds the ScanObservations and persists the results (ADR 0009).
"""

from sentinel_analysis.engine import RULESET_VERSION, analyze
from sentinel_analysis.model import (
    AnalysisResult,
    Category,
    Confidence,
    DetectionType,
    FindingCandidate,
    RuleError,
    RuleMeta,
    Severity,
    SubjectType,
)
from sentinel_analysis.observations import (
    AssetObs,
    CookieObs,
    EndpointObs,
    EventObs,
    ResponseObs,
    ScanInfo,
    ScanObservations,
)
from sentinel_analysis.rules import REGISTRY

__version__ = "0.1.0"

__all__ = [
    "REGISTRY",
    "RULESET_VERSION",
    "AnalysisResult",
    "AssetObs",
    "Category",
    "Confidence",
    "CookieObs",
    "DetectionType",
    "EndpointObs",
    "EventObs",
    "FindingCandidate",
    "ResponseObs",
    "RuleError",
    "RuleMeta",
    "ScanInfo",
    "ScanObservations",
    "Severity",
    "SubjectType",
    "__version__",
    "analyze",
]
