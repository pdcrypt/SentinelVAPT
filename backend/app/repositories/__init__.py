"""Database access. The only layer that issues queries."""

from app.repositories.assessment import AssessmentRepository
from app.repositories.project import ProjectRepository
from app.repositories.scan import QueuedCandidate, ScanRepository
from app.repositories.scan_results import ScanResultRepository
from app.repositories.target import TargetRepository
from app.repositories.target_authorization import TargetAuthorizationRepository

__all__ = [
    "AssessmentRepository",
    "ProjectRepository",
    "QueuedCandidate",
    "ScanRepository",
    "ScanResultRepository",
    "TargetAuthorizationRepository",
    "TargetRepository",
]
