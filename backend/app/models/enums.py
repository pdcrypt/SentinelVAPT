from enum import StrEnum


class TargetEnvironment(StrEnum):
    """Where a target lives. Lab targets are restricted to private/lab addresses."""

    LOCAL_LAB = "local_lab"
    AUTHORIZED_EXTERNAL = "authorized_external"


class AuthorizationStatus(StrEnum):
    """Computed from the authorization window; not stored."""

    PENDING = "pending"
    ACTIVE = "active"
    EXPIRED = "expired"


class AssessmentStatus(StrEnum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
