"""The scan grant: the explicit contract between the backend and the scanner.

The scanner cannot read the database, so the caller passes a frozen snapshot of
the assessment and the authorization record it runs under. The scanner does not
take the snapshot on trust: validate_grant() re-checks everything it can before
any network I/O, and the window is re-checked before every request.

What the scanner cannot verify is that the snapshot matches the database; the
backend builds it under the assessment/target locks (Phase 3). Forging a grant
requires code execution inside the worker, which is outside this boundary.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sentinel_scanner.errors import GrantRejected, ScopeViolation
from sentinel_scanner.scope import ScopePolicy

# Phase 2 supports lab targets only (see docs/adr/0007).
SUPPORTED_ENVIRONMENTS = frozenset({"local_lab"})
REQUIRED_ASSESSMENT_STATUS = "in_progress"


@dataclass(frozen=True)
class ScopeSnapshot:
    base_url: str
    environment: str
    in_scope_hosts: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    in_scope_path_prefixes: tuple[str, ...]
    excluded_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanGrant:
    target_id: uuid.UUID
    assessment_id: uuid.UUID
    authorization_id: uuid.UUID
    authorization_version: int
    assessment_status: str
    valid_from: datetime
    valid_until: datetime
    scope: ScopeSnapshot

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanGrant":
        scope = data["scope"]
        return cls(
            target_id=uuid.UUID(str(data["target_id"])),
            assessment_id=uuid.UUID(str(data["assessment_id"])),
            authorization_id=uuid.UUID(str(data["authorization_id"])),
            authorization_version=int(data["authorization_version"]),
            assessment_status=str(data["assessment_status"]),
            valid_from=_parse_datetime(data["valid_from"]),
            valid_until=_parse_datetime(data["valid_until"]),
            scope=ScopeSnapshot(
                base_url=str(scope["base_url"]),
                environment=str(scope["environment"]),
                in_scope_hosts=tuple(scope["in_scope_hosts"]),
                allowed_ports=tuple(int(p) for p in scope["allowed_ports"]),
                in_scope_path_prefixes=tuple(scope["in_scope_path_prefixes"]),
                excluded_paths=tuple(scope.get("excluded_paths", ())),
            ),
        )

    def is_active_at(self, now: datetime) -> bool:
        return self.valid_from <= now < self.valid_until


def _parse_datetime(value: Any) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(str(value))


def validate_grant(grant: ScanGrant, now: datetime) -> ScopePolicy:
    """Return the scope policy for an acceptable grant, or raise GrantRejected."""
    if grant.valid_from.tzinfo is None or grant.valid_until.tzinfo is None:
        raise GrantRejected("naive_datetime", "authorization window must be timezone-aware")
    if now.tzinfo is None:
        raise GrantRejected("naive_datetime", "clock must be timezone-aware")
    if grant.assessment_status != REQUIRED_ASSESSMENT_STATUS:
        raise GrantRejected(
            "assessment_not_active",
            f"assessment is '{grant.assessment_status}'; scans require an in-progress assessment",
        )
    if grant.authorization_version < 1:
        raise GrantRejected("invalid_grant", "authorization version must be positive")
    if grant.valid_until <= grant.valid_from:
        raise GrantRejected("invalid_grant", "authorization window is empty")
    if not grant.is_active_at(now):
        state = "not yet active" if now < grant.valid_from else "expired"
        raise GrantRejected("authorization_not_active", f"authorization is {state}")
    if grant.scope.environment not in SUPPORTED_ENVIRONMENTS:
        raise GrantRejected(
            "environment_not_supported",
            f"'{grant.scope.environment}' targets cannot be scanned; only local_lab is supported",
        )

    try:
        policy = ScopePolicy(
            hosts=grant.scope.in_scope_hosts,
            ports=grant.scope.allowed_ports,
            path_prefixes=grant.scope.in_scope_path_prefixes,
            excluded_paths=grant.scope.excluded_paths,
            lab_only=True,
        )
        policy.check_url(grant.scope.base_url)
    except ScopeViolation as exc:
        raise GrantRejected("invalid_scope", f"scope rejected: {exc.message}") from None
    return policy
