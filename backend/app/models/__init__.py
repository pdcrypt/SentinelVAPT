"""SQLAlchemy ORM models. Import every model here so Alembic sees them."""

from app.models.assessment import Assessment
from app.models.project import Project
from app.models.scan import Scan
from app.models.scan_results import Asset, Endpoint, EndpointCookie, Evidence, ScanLog
from app.models.target import Target
from app.models.target_authorization import TargetAuthorization

__all__ = [
    "Assessment",
    "Asset",
    "Endpoint",
    "EndpointCookie",
    "Evidence",
    "Project",
    "Scan",
    "ScanLog",
    "Target",
    "TargetAuthorization",
]
