"""SQLAlchemy ORM models. Import every model here so Alembic sees them."""

from app.models.analysis import (
    AnalysisRun,
    Finding,
    FindingEvidence,
    FindingStatusChange,
    RuleVersion,
)
from app.models.assessment import Assessment
from app.models.comparison import Comparison, ComparisonCoverageEvidence, ComparisonRecord
from app.models.project import Project
from app.models.report import Report, ReportArtifact, ReportEvidence, ReportFinding
from app.models.retest_report import RetestReport, RetestReportArtifact, RetestReportEvidence
from app.models.scan import Scan
from app.models.scan_results import Asset, Endpoint, EndpointCookie, Evidence, ScanLog
from app.models.target import Target
from app.models.target_authorization import TargetAuthorization

__all__ = [
    "AnalysisRun",
    "Assessment",
    "Asset",
    "Comparison",
    "ComparisonCoverageEvidence",
    "ComparisonRecord",
    "Endpoint",
    "EndpointCookie",
    "Evidence",
    "Finding",
    "FindingEvidence",
    "FindingStatusChange",
    "Project",
    "Report",
    "ReportArtifact",
    "ReportEvidence",
    "ReportFinding",
    "RetestReport",
    "RetestReportArtifact",
    "RetestReportEvidence",
    "RuleVersion",
    "Scan",
    "ScanLog",
    "Target",
    "TargetAuthorization",
]
