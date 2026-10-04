"""Database access. The only layer that issues queries."""

from app.repositories.analysis import AnalysisRepository
from app.repositories.assessment import AssessmentRepository
from app.repositories.comparison import ComparisonRepository
from app.repositories.project import ProjectRepository
from app.repositories.report import ReportRepository
from app.repositories.scan import QueuedCandidate, ScanRepository
from app.repositories.scan_results import ScanResultRepository
from app.repositories.target import TargetRepository
from app.repositories.target_authorization import TargetAuthorizationRepository

__all__ = [
    "AnalysisRepository",
    "AssessmentRepository",
    "ComparisonRepository",
    "ProjectRepository",
    "QueuedCandidate",
    "ReportRepository",
    "ScanRepository",
    "ScanResultRepository",
    "TargetAuthorizationRepository",
    "TargetRepository",
]
