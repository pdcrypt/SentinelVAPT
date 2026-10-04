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


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


ACTIVE_SCAN_STATUSES = frozenset({ScanStatus.QUEUED, ScanStatus.RUNNING})
TERMINAL_SCAN_STATUSES = frozenset({ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED})


class AnalysisStatus(StrEnum):
    QUEUED = "queued"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingStatus(StrEnum):
    """Phase 4 triage states. fixed / retest_required arrive with retesting."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


STATUSES_REQUIRING_REASON = frozenset({FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK})


class ReportStatus(StrEnum):
    QUEUED = "queued"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class ReportKind(StrEnum):
    DRAFT = "draft"
    FINAL = "final"


class ReportClassification(StrEnum):
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ReportFormat(StrEnum):
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


class ComparisonStatus(StrEnum):
    """No running state: a comparison is computed and stored in one transaction."""

    QUEUED = "queued"
    COMPLETED = "completed"
    FAILED = "failed"


class ComparisonState(StrEnum):
    """Comparison policy cmp-1 states (ADR 0011). Separate from triage status."""

    NEW = "new"
    REOPENED = "reopened"
    UNCHANGED = "unchanged"
    STILL_OPEN = "still_open"
    FIXED = "fixed"
    DISMISSED = "dismissed"
    NOT_RETESTED = "not_retested"
    NOT_COMPARABLE = "not_comparable"


# --- Phase 9: identity and authorization (ADR 0014) ------------------------------


class GlobalRole(StrEnum):
    """Platform-wide role. Grants no project or target access by itself."""

    ADMIN = "admin"  # manages user accounts and reads the global audit log
    USER = "user"


class ProjectRole(StrEnum):
    """A member's role within one project."""

    OWNER = "owner"  # members, targets, authorization acknowledgment, deletion
    OPERATOR = "operator"  # runs the workflow: assessments, scans, triage, reports
    VIEWER = "viewer"  # read-only


class SessionRevocationReason(StrEnum):
    LOGOUT = "logout"
    PASSWORD_CHANGED = "password_changed"  # noqa: S105  # a revocation reason, not a secret
    USER_DISABLED = "user_disabled"
    ROLE_CHANGED = "role_changed"
    REVOKED_BY_USER = "revoked_by_user"
    REVOKED_BY_ADMIN = "revoked_by_admin"


class AuditActorType(StrEnum):
    USER = "user"  # an authenticated platform user
    SYSTEM = "system"  # a worker or a server-side command
    ANONYMOUS = "anonymous"  # an unauthenticated request (e.g. a failed login)


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"
