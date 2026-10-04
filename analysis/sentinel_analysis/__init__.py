"""SentinelVAPT deterministic analysis.

Turns a scan's persisted, redacted observations into explainable finding
candidates, and compares a retest's findings with its baseline (comparison
policy cmp-1). Offline and deterministic: no network, no database, no AI.
The backend builds the inputs and persists the results (ADR 0009, 0011).
"""

from sentinel_analysis.comparison import (
    POLICY_VERSION,
    ComparisonRecord,
    CurrentRun,
    FindingSnapshot,
    State,
    classify,
)
from sentinel_analysis.coverage import Coverage, coverage
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
    "POLICY_VERSION",
    "REGISTRY",
    "RULESET_VERSION",
    "AnalysisResult",
    "AssetObs",
    "Category",
    "ComparisonRecord",
    "Confidence",
    "CookieObs",
    "Coverage",
    "CurrentRun",
    "DetectionType",
    "EndpointObs",
    "EventObs",
    "FindingCandidate",
    "FindingSnapshot",
    "ResponseObs",
    "RuleError",
    "RuleMeta",
    "ScanInfo",
    "ScanObservations",
    "Severity",
    "State",
    "SubjectType",
    "__version__",
    "analyze",
    "classify",
    "coverage",
]
