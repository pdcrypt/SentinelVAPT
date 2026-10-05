"""The audit vocabulary (ADR 0014, Phase 9 M6): every action the platform
records, what it means, and the only metadata keys it may carry.

The same list is the `audit_actions` table (migration c4f7a2e9d1b6), and
audit_events.action is a foreign key to it: an action outside this list
cannot be stored, whatever code tries. tests/unit/test_audit_model.py keeps
the two in step.

Metadata is never request data. Each action has a fixed set of keys; values
are scalars (strings of at most 256 characters without control characters,
integers, booleans or null). The database additionally refuses secret-like
keys, nested values and more than 4 KB (M1).
"""

import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Any


class AuditAction(StrEnum):
    # Authentication (M2; session_rejected and password_change_required since M6)
    AUTH_LOGIN = "auth.login"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_LOGOUT = "auth.logout"
    AUTH_PASSWORD_CHANGED = "auth.password_changed"  # noqa: S105  # an action name
    AUTH_PASSWORD_CHANGE_FAILED = "auth.password_change_failed"  # noqa: S105  # an action name
    AUTH_SESSION_REJECTED = "auth.session_rejected"
    AUTH_PASSWORD_CHANGE_REQUIRED = "auth.password_change_required"  # noqa: S105  # an action name
    # Accounts and the platform (server-side commands)
    USER_CREATED = "user.created"
    USER_DISABLED = "user.disabled"
    PLATFORM_AUTH_ENFORCED = "platform.auth_enforced"
    # Authorization decisions (denials only)
    AUTHZ_DENIED = "authz.denied"
    # Projects
    PROJECT_CREATED = "project.created"
    PROJECT_UPDATED = "project.updated"
    PROJECT_DELETED = "project.deleted"
    PROJECT_CLAIMED = "project.claim"  # M4 name, kept
    # Targets and their authorization records
    TARGET_CREATED = "target.created"
    TARGET_UPDATED = "target.updated"
    TARGET_DELETED = "target.deleted"
    TARGET_AUTHORIZATION_CREATED = "target_authorization.created"
    # Assessments and retests
    ASSESSMENT_CREATED = "assessment.created"
    ASSESSMENT_UPDATED = "assessment.updated"
    ASSESSMENT_DELETED = "assessment.deleted"
    ASSESSMENT_STARTED = "assessment.started"
    ASSESSMENT_START_REFUSED = "assessment.start_refused"
    ASSESSMENT_COMPLETED = "assessment.completed"
    ASSESSMENT_CANCELLED = "assessment.cancelled"
    RETEST_CREATED = "retest.created"
    # Scans (requests by users; lifecycle by workers)
    SCAN_REQUESTED = "scan.requested"
    SCAN_REQUEST_REFUSED = "scan.request_refused"
    SCAN_CANCEL_REQUESTED = "scan.cancel_requested"
    SCAN_REFUSED = "scan.refused"  # the worker's own grant check refused it
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_CANCELLED = "scan.cancelled"
    SCAN_FAILED = "scan.failed"
    ANALYSIS_COMPLETED = "analysis.completed"
    ANALYSIS_FAILED = "analysis.failed"
    # Findings
    FINDING_TRIAGED = "finding.triaged"
    # Comparisons and reports
    COMPARISON_REQUESTED = "comparison.requested"
    COMPARISON_COMPLETED = "comparison.completed"
    COMPARISON_FAILED = "comparison.failed"
    REPORT_REQUESTED = "report.requested"
    REPORT_COMPLETED = "report.completed"
    REPORT_FAILED = "report.failed"
    RETEST_REPORT_REQUESTED = "retest_report.requested"
    RETEST_REPORT_COMPLETED = "retest_report.completed"
    RETEST_REPORT_FAILED = "retest_report.failed"


A = AuditAction
DESCRIPTIONS: Mapping[AuditAction, str] = {
    A.AUTH_LOGIN: "A user signed in (a session was issued).",
    A.AUTH_LOGIN_FAILED: "A sign-in was refused (unknown user, disabled, throttled, bad password).",
    A.AUTH_LOGOUT: "A user ended their session.",
    A.AUTH_PASSWORD_CHANGED: "A user changed their password (all their sessions were replaced).",
    A.AUTH_PASSWORD_CHANGE_FAILED: "A password change was refused.",
    A.AUTH_SESSION_REJECTED: "A revoked session, or one of a disabled user, was presented.",
    A.AUTH_PASSWORD_CHANGE_REQUIRED: "A request was refused until the user changes their password.",
    A.USER_CREATED: "An account was created by a server-side command.",
    A.USER_DISABLED: "An account was disabled and its sessions revoked.",
    A.PLATFORM_AUTH_ENFORCED: "The authentication cutover was recorded.",
    A.AUTHZ_DENIED: "A user was refused a permission (project or global).",
    A.PROJECT_CREATED: "A project was created; its creator became its owner.",
    A.PROJECT_UPDATED: "A project was renamed or described.",
    A.PROJECT_DELETED: "A project was deleted.",
    A.PROJECT_CLAIMED: "A legacy project was given its first owner by a server-side command.",
    A.TARGET_CREATED: "A target was created.",
    A.TARGET_UPDATED: "A target was renamed or re-scoped.",
    A.TARGET_DELETED: "A target was deleted.",
    A.TARGET_AUTHORIZATION_CREATED: "A target authorization was acknowledged (a new version).",
    A.ASSESSMENT_CREATED: "An assessment was planned.",
    A.ASSESSMENT_UPDATED: "An assessment was renamed or described.",
    A.ASSESSMENT_DELETED: "An assessment was deleted.",
    A.ASSESSMENT_STARTED: "An assessment started.",
    A.ASSESSMENT_START_REFUSED: "An assessment could not start: the target authorization was not "
    "usable.",
    A.ASSESSMENT_COMPLETED: "An assessment was completed.",
    A.ASSESSMENT_CANCELLED: "An assessment was cancelled.",
    A.RETEST_CREATED: "A retest of a completed assessment was planned.",
    A.SCAN_REQUESTED: "A scan was requested.",
    A.SCAN_REQUEST_REFUSED: "A scan request was refused (lifecycle or target authorization).",
    A.SCAN_CANCEL_REQUESTED: "A user cancelled, or asked to cancel, a scan.",
    A.SCAN_REFUSED: "A worker refused a queued scan: its grant failed the claim-time check.",
    A.SCAN_STARTED: "A worker started a scan.",
    A.SCAN_COMPLETED: "A scan finished.",
    A.SCAN_CANCELLED: "A scan stopped after a cancellation.",
    A.SCAN_FAILED: "A scan failed (including a lost worker).",
    A.ANALYSIS_COMPLETED: "A scan's analysis finished.",
    A.ANALYSIS_FAILED: "A scan's analysis failed.",
    A.FINDING_TRIAGED: "A finding's triage status changed.",
    A.COMPARISON_REQUESTED: "A retest comparison was requested.",
    A.COMPARISON_COMPLETED: "A comparison was computed.",
    A.COMPARISON_FAILED: "A comparison failed.",
    A.REPORT_REQUESTED: "A report was requested (its snapshot frozen).",
    A.REPORT_COMPLETED: "A report's artifacts were generated.",
    A.REPORT_FAILED: "A report could not be generated.",
    A.RETEST_REPORT_REQUESTED: "A retest report was requested.",
    A.RETEST_REPORT_COMPLETED: "A retest report's artifacts were generated.",
    A.RETEST_REPORT_FAILED: "A retest report could not be generated.",
}

# The only metadata keys each action may carry ("source" is added to every
# event from the request context).
METADATA_KEYS: Mapping[AuditAction, frozenset[str]] = {
    A.AUTH_LOGIN_FAILED: frozenset({"reason"}),
    A.AUTH_PASSWORD_CHANGE_FAILED: frozenset({"reason"}),
    A.AUTH_SESSION_REJECTED: frozenset({"reason", "user_id"}),
    A.USER_CREATED: frozenset({"global_role", "bootstrap"}),
    A.USER_DISABLED: frozenset({"sessions_revoked"}),
    A.PROJECT_CLAIMED: frozenset({"owner_user_id"}),
    A.AUTHZ_DENIED: frozenset({"permission", "reason", "role"}),
    A.PROJECT_UPDATED: frozenset({"renamed"}),
    A.TARGET_UPDATED: frozenset({"renamed", "scope_changed"}),
    A.TARGET_AUTHORIZATION_CREATED: frozenset({"target_id", "version", "valid_until"}),
    A.ASSESSMENT_START_REFUSED: frozenset({"reason"}),
    A.RETEST_CREATED: frozenset({"parent_assessment_id", "baseline_scan_id"}),
    A.SCAN_REQUEST_REFUSED: frozenset({"reason"}),
    A.SCAN_CANCEL_REQUESTED: frozenset({"status"}),
    A.SCAN_REFUSED: frozenset({"reason"}),
    A.SCAN_COMPLETED: frozenset({"requests_sent", "endpoints_count"}),
    A.SCAN_FAILED: frozenset({"reason"}),
    A.ANALYSIS_COMPLETED: frozenset({"scan_id", "findings_count"}),
    A.ANALYSIS_FAILED: frozenset({"scan_id"}),
    A.FINDING_TRIAGED: frozenset({"from_status", "to_status"}),
    A.COMPARISON_REQUESTED: frozenset({"created", "scan_id"}),
    A.COMPARISON_FAILED: frozenset({"reason"}),
    A.REPORT_REQUESTED: frozenset({"kind", "scan_id"}),
    A.REPORT_FAILED: frozenset({"reason"}),
    A.RETEST_REPORT_REQUESTED: frozenset({"kind", "created", "comparison_id"}),
    A.RETEST_REPORT_FAILED: frozenset({"reason"}),
}

# Resource types an audit event may name: the project-scoped resources plus
# platform identities.
PLATFORM_RESOURCES = frozenset({"user", "session"})

MAX_STRING = 256
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class AuditMetadataError(ValueError):
    """Metadata that is not allowed for the action. Always a defect in the
    calling code (metadata never comes from requests)."""


def audit_action(action: object) -> AuditAction:
    if isinstance(action, str):
        try:
            return AuditAction(action)
        except ValueError:
            pass
    raise AuditMetadataError(f"unknown audit action: {action!r}")


def validate_metadata(action: AuditAction, metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    """The metadata of an event, checked against the action's allowlist."""
    allowed = METADATA_KEYS.get(action, frozenset())
    out: dict[str, Any] = {}
    for key, value in (metadata or {}).items():
        if key not in allowed:
            raise AuditMetadataError(f"{action.value} does not record {key!r}")
        if isinstance(value, bool) or value is None or isinstance(value, int):
            out[key] = value
        elif isinstance(value, str):
            if len(value) > MAX_STRING or _CONTROL.search(value):
                raise AuditMetadataError(f"{action.value}.{key} is not a short plain string")
            out[key] = value
        else:
            raise AuditMetadataError(f"{action.value}.{key} must be a scalar")
    return out
