"""Builds the scanner's ScanGrant from authoritative database state.

Used twice with the same rules: when a scan is requested (to refuse early) and
when the worker claims it (because state may have changed in between). Callers
must hold the assessment and target row locks. The scan's stored
grant_snapshot is an audit record of the result; it is never read back as
authorization state (ADR 0008).
"""

from dataclasses import asdict
from datetime import datetime
from typing import Any

from app.core.errors import ScanNotAllowedError
from app.models import Assessment, Target, TargetAuthorization
from app.models.enums import AssessmentStatus, AuthorizationStatus, TargetEnvironment
from app.services.scope import authorization_status
from sentinel_scanner import CrawlOptions, DiscoveryConfig, ScanLimits
from sentinel_scanner.errors import GrantRejected
from sentinel_scanner.grant import ScanGrant, ScopeSnapshot, validate_grant

# Phase 3 scans lab targets only (ADR 0007/0008).
SCANNABLE_ENVIRONMENTS = frozenset({TargetEnvironment.LOCAL_LAB})


def check_scannable(
    assessment: Assessment,
    target: Target,
    authorization: TargetAuthorization,
    now: datetime,
) -> None:
    """Raise ScanNotAllowedError unless a scan may run right now."""
    if assessment.target_id != target.id or authorization.target_id != target.id:
        raise ScanNotAllowedError(
            "inconsistent_state", "assessment, target and authorization disagree"
        )
    if assessment.status is not AssessmentStatus.IN_PROGRESS:
        raise ScanNotAllowedError(
            "assessment_not_in_progress",
            f"the assessment is {assessment.status}; scans require an in-progress assessment",
        )
    if (
        target.current_authorization_id != assessment.authorization_id
        or authorization.id != assessment.authorization_id
    ):
        raise ScanNotAllowedError(
            "authorization_superseded",
            "the target was re-authorized after this assessment was planned; plan a new "
            "assessment under the current authorization",
        )
    status = authorization_status(authorization.valid_from, authorization.valid_until, now)
    if status is not AuthorizationStatus.ACTIVE:
        raise ScanNotAllowedError(
            "authorization_not_active", f"the target's authorization is {status}"
        )
    if authorization.environment not in SCANNABLE_ENVIRONMENTS:
        raise ScanNotAllowedError(
            "environment_not_supported",
            f"{authorization.environment} targets cannot be scanned; only local_lab is supported",
        )


def build_scan_grant(
    assessment: Assessment,
    target: Target,
    authorization: TargetAuthorization,
    now: datetime,
) -> ScanGrant:
    """Check the rules, build the grant from the rows, then run the scanner's
    own validation on it (the same check the scanner repeats itself)."""
    check_scannable(assessment, target, authorization, now)
    grant = ScanGrant(
        target_id=target.id,
        assessment_id=assessment.id,
        authorization_id=authorization.id,
        authorization_version=authorization.version,
        assessment_status=assessment.status.value,
        valid_from=authorization.valid_from,
        valid_until=authorization.valid_until,
        scope=ScopeSnapshot(
            base_url=authorization.base_url,
            environment=authorization.environment.value,
            in_scope_hosts=tuple(authorization.in_scope_hosts),
            allowed_ports=tuple(authorization.allowed_ports),
            in_scope_path_prefixes=tuple(authorization.in_scope_path_prefixes),
            excluded_paths=tuple(authorization.excluded_paths),
        ),
    )
    try:
        validate_grant(grant, now)
    except GrantRejected as exc:
        raise ScanNotAllowedError(
            f"grant_{exc.code}", f"the scanner would refuse: {exc.message}"
        ) from None
    return grant


def grant_snapshot(grant: ScanGrant) -> dict[str, Any]:
    """JSON audit record of exactly what the scanner is given."""
    return {
        "target_id": str(grant.target_id),
        "assessment_id": str(grant.assessment_id),
        "authorization_id": str(grant.authorization_id),
        "authorization_version": grant.authorization_version,
        "assessment_status": grant.assessment_status,
        "valid_from": grant.valid_from.isoformat(),
        "valid_until": grant.valid_until.isoformat(),
        "scope": {
            "base_url": grant.scope.base_url,
            "environment": grant.scope.environment,
            "in_scope_hosts": list(grant.scope.in_scope_hosts),
            "allowed_ports": list(grant.scope.allowed_ports),
            "in_scope_path_prefixes": list(grant.scope.in_scope_path_prefixes),
            "excluded_paths": list(grant.scope.excluded_paths),
        },
    }


def scan_config_record(*, allow_untrusted_tls: bool) -> dict[str, Any]:
    """What a scan will run with. Only allow_untrusted_tls is chosen per scan;
    limits and crawl options are the scanner's defaults, recorded for audit."""
    return {
        "allow_untrusted_tls": allow_untrusted_tls,
        "limits": asdict(ScanLimits()),
        "crawl": asdict(CrawlOptions()),
    }


def discovery_config(config_record: dict[str, Any]) -> DiscoveryConfig:
    """Build the scanner config. Only the TLS opt-in is taken from the record;
    limits always come from the scanner's defaults, never from stored data."""
    return DiscoveryConfig(verify_tls=config_record.get("allow_untrusted_tls") is not True)
