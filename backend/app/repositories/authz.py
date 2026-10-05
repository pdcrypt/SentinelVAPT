"""Project resolution for authorization (ADR 0014, Phase 9 M3).

A resource's project is derived from the resource's own rows, following the
real containment chain to `targets.project_id` (the only project reference;
targets cannot change project through the API). Composite foreign keys keep
every scan, finding, report, comparison and retest report on one target, so
the row's own `target_id` (where it has one) is authoritative for its whole
chain.

Each lookup returns, in ONE query, whether the resource exists, its project,
and the caller's membership role (LEFT JOIN project_members). Callers turn
"missing", "another project" and "not a member" into the same 404. More than
one row for a key is a defect and raises (fail closed).
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass

from sqlalchemy import Select, select, text
from sqlalchemy.orm import Session

from app.core.authz import AuthorizationConfigError, ResourceType
from app.models import Project, ProjectMember
from app.models.enums import ProjectRole


@dataclass(frozen=True)
class ResolverSpec:
    """`source` is a FROM clause ending in a table aliased `t` (targets),
    except for projects; `keys` are the key names, each compared with a
    bound parameter of the same name (against `r.<key>` unless `columns`
    names the column); `uuid_keys` must be UUIDs."""

    source: str
    keys: tuple[str, ...]
    uuid_keys: frozenset[str]
    project_column: str = "t.project_id"
    columns: Mapping[str, str] | None = None


def _via_scan(table: str) -> ResolverSpec:
    return ResolverSpec(
        f"{table} r JOIN scans s ON s.id = r.scan_id JOIN targets t ON t.id = s.target_id",
        ("id",),
        frozenset({"id"}),
    )


_ID = ("id",)
_UUID_ID = frozenset({"id"})

RESOLVERS: Mapping[ResourceType, ResolverSpec] = {
    ResourceType.PROJECT: ResolverSpec("projects p", _ID, _UUID_ID, project_column="p.id"),
    ResourceType.TARGET: ResolverSpec("targets t", _ID, _UUID_ID),
    ResourceType.TARGET_AUTHORIZATION: ResolverSpec(
        "target_authorizations r JOIN targets t ON t.id = r.target_id", _ID, _UUID_ID
    ),
    ResourceType.ASSESSMENT: ResolverSpec(
        "assessments r JOIN targets t ON t.id = r.target_id", _ID, _UUID_ID
    ),
    # A retest is an assessment with a parent; anything else does not exist as one.
    ResourceType.RETEST_ASSESSMENT: ResolverSpec(
        "assessments r JOIN targets t ON t.id = r.target_id "
        "AND r.retest_of_assessment_id IS NOT NULL",
        _ID,
        _UUID_ID,
    ),
    ResourceType.SCAN: ResolverSpec("scans r JOIN targets t ON t.id = r.target_id", _ID, _UUID_ID),
    ResourceType.SCAN_LOG: _via_scan("scan_logs"),
    ResourceType.ASSET: _via_scan("assets"),
    ResourceType.ENDPOINT: _via_scan("endpoints"),
    ResourceType.EVIDENCE: _via_scan("evidence"),
    ResourceType.ANALYSIS_RUN: _via_scan("analysis_runs"),
    ResourceType.FINDING: ResolverSpec(
        "findings r JOIN targets t ON t.id = r.target_id", _ID, _UUID_ID
    ),
    ResourceType.REPORT: ResolverSpec(
        "reports r JOIN targets t ON t.id = r.target_id", _ID, _UUID_ID
    ),
    ResourceType.REPORT_ARTIFACT: ResolverSpec(
        "report_artifacts r JOIN reports p ON p.id = r.report_id "
        "JOIN targets t ON t.id = p.target_id",
        ("report_id", "format"),
        frozenset({"report_id"}),
    ),
    ResourceType.REPORT_FINDING: ResolverSpec(
        "report_findings r JOIN reports p ON p.id = r.report_id "
        "JOIN targets t ON t.id = p.target_id",
        ("report_id", "finding_id"),
        frozenset({"report_id", "finding_id"}),
    ),
    ResourceType.REPORT_EVIDENCE: ResolverSpec(
        "report_evidence r JOIN reports p ON p.id = r.report_id "
        "JOIN targets t ON t.id = p.target_id",
        ("report_id", "evidence_id"),
        frozenset({"report_id", "evidence_id"}),
    ),
    ResourceType.COMPARISON: ResolverSpec(
        "comparisons r JOIN targets t ON t.id = r.target_id", _ID, _UUID_ID
    ),
    ResourceType.ASSESSMENT_COMPARISON: ResolverSpec(
        "comparisons r JOIN targets t ON t.id = r.target_id",
        ("assessment_id", "comparison_id"),
        frozenset({"assessment_id", "comparison_id"}),
        columns={"assessment_id": "r.current_assessment_id", "comparison_id": "r.id"},
    ),
    ResourceType.COMPARISON_RECORD: ResolverSpec(
        "comparison_records r JOIN comparisons c ON c.id = r.comparison_id "
        "JOIN targets t ON t.id = c.target_id",
        ("comparison_id", "fingerprint"),
        frozenset({"comparison_id"}),
    ),
    ResourceType.COMPARISON_COVERAGE_EVIDENCE: ResolverSpec(
        "comparison_coverage_evidence r JOIN comparisons c ON c.id = r.comparison_id "
        "JOIN targets t ON t.id = c.target_id",
        ("comparison_id", "fingerprint", "evidence_id"),
        frozenset({"comparison_id", "evidence_id"}),
    ),
    ResourceType.RETEST_REPORT: ResolverSpec(
        "retest_reports r JOIN targets t ON t.id = r.target_id", _ID, _UUID_ID
    ),
    ResourceType.RETEST_REPORT_ARTIFACT: ResolverSpec(
        "retest_report_artifacts r JOIN retest_reports p ON p.id = r.report_id "
        "JOIN targets t ON t.id = p.target_id",
        ("report_id", "format"),
        frozenset({"report_id"}),
    ),
    ResourceType.RETEST_REPORT_EVIDENCE: ResolverSpec(
        "retest_report_evidence r JOIN retest_reports p ON p.id = r.report_id "
        "JOIN targets t ON t.id = p.target_id",
        ("report_id", "role", "evidence_id"),
        frozenset({"report_id", "evidence_id"}),
    ),
}

# Key columns of each resource's own table, by the resolver alias used above.
_KEY_COLUMNS: Mapping[ResourceType, Mapping[str, str]] = {
    resource: {key: (spec.columns[key] if spec.columns else
                     "p.id" if resource is ResourceType.PROJECT else
                     "t.id" if resource is ResourceType.TARGET else f"r.{key}")
               for key in spec.keys}
    for resource, spec in RESOLVERS.items()
}  # fmt: skip


@dataclass(frozen=True)
class Resolution:
    """The resource exists in `project_id`; `role` is the caller's membership
    there, or None for a non-member."""

    project_id: uuid.UUID
    role: ProjectRole | None


def _spec(resource: object) -> ResolverSpec:
    if not isinstance(resource, ResourceType) or resource not in RESOLVERS:
        raise AuthorizationConfigError(f"no project resolver for {resource!r}")
    return RESOLVERS[resource]


def normalize_key(resource: ResourceType, key: Mapping[str, str]) -> dict[str, object] | None:
    """Validates the key for the resource type; None if a value cannot be a
    valid key (e.g. not a UUID), which callers treat as not found."""
    spec = _spec(resource)
    if set(key) != set(spec.keys):
        raise AuthorizationConfigError(
            f"{resource.value} is identified by {spec.keys}, got {tuple(sorted(key))}"
        )
    values: dict[str, object] = {}
    for name, raw in key.items():
        if name in spec.uuid_keys:
            try:
                values[name] = uuid.UUID(str(raw))
            except ValueError:
                return None
        else:
            values[name] = str(raw)
    return values


class ProjectResolver:
    def __init__(self, session: Session) -> None:
        self.session = session

    def resolve(
        self, resource: ResourceType, key: Mapping[str, str], user_id: uuid.UUID
    ) -> Resolution | None:
        """None when the resource does not exist (or the key is malformed)."""
        spec = _spec(resource)
        values = normalize_key(resource, key)
        if values is None:
            return None
        columns = _KEY_COLUMNS[resource]
        where = " AND ".join(f"{columns[name]} = :k_{name}" for name in spec.keys)
        sql = (
            f"SELECT {spec.project_column} AS project_id, m.role AS role "  # noqa: S608  # fixed specs
            f"FROM {spec.source} "
            f"LEFT JOIN project_members m ON m.project_id = {spec.project_column} "
            f"AND m.user_id = :user_id WHERE {where}"
        )
        params = {f"k_{name}": value for name, value in values.items()}
        rows = self.session.execute(text(sql), {**params, "user_id": user_id}).all()
        if not rows:
            return None
        if len(rows) > 1:
            raise AuthorizationConfigError(f"{resource.value} key resolved to several rows")
        project_id, role = rows[0]
        return Resolution(project_id, ProjectRole(role) if role is not None else None)

    @staticmethod
    def member_projects(user_id: uuid.UUID) -> Select[uuid.UUID]:
        """Ids of the projects the user is a member of; for filtering lists
        (e.g. Project.id.in_(...)). Global roles play no part."""
        return select(ProjectMember.project_id).where(ProjectMember.user_id == user_id)

    def visible_projects(self, user_id: uuid.UUID) -> Select[Project]:
        return select(Project).where(Project.id.in_(self.member_projects(user_id)))
