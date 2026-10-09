"""The security posture dashboard (ADR 0015).

Assembles the read models from PostureRepository's aggregates. It only sums
grouped counts and attaches "latest" rows that the queries already selected;
it never loads findings, scans or comparisons one by one. Callers pass
projects that are already authorized: one project resolved by the route's
project.read descriptor, or the caller's memberships (never ids from a
request).
"""

import uuid
from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import Any, get_args

from app.models.enums import ComparisonState, FindingStatus, ProjectRole
from app.repositories.posture import (
    MAX_TARGETS,
    LatestComparison,
    LatestReport,
    LatestScan,
    PostureRepository,
)
from app.schemas.finding import SeverityLiteral

# The backend's own severity values (the findings check constraint), in
# analysis order; the rule engine stays behind its package boundary.
SEVERITY_ORDER: tuple[str, ...] = get_args(SeverityLiteral)  # critical … informational
# The reports' order (sentinel_reports.snapshot.STATUS_ORDER); a test keeps it
# equal to the FindingStatus enum's values.
STATUS_ORDER = ("open", "confirmed", "accepted_risk", "false_positive")
STATE_ORDER = tuple(s.value for s in ComparisonState)
FALSE_POSITIVE = FindingStatus.FALSE_POSITIVE.value
OPEN = FindingStatus.OPEN.value


def _ordered(counts: dict[str, int], order: Sequence[str]) -> dict[str, int]:
    """Every known key in order (zeros included), then any stored value the
    enums do not know, so nothing persisted is hidden."""
    out = {key: counts.get(key, 0) for key in order}
    out.update({k: v for k, v in sorted(counts.items()) if k not in out})
    return out


def finding_counts(rows: Iterable[tuple[str, str, int]]) -> dict[str, Any]:
    """Counts from (severity, triage status, count) groups, per ADR 0015."""
    by_severity: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    total = active = open_ = 0
    for severity, status, count in rows:
        total += count
        by_status[status] += count
        if status != FALSE_POSITIVE:
            active += count
            by_severity[severity] += count
        if status == OPEN:
            open_ += count
    return {
        "total": total,
        "active": active,
        "open": open_,
        "by_severity": _ordered(by_severity, SEVERITY_ORDER),
        "by_status": _ordered(by_status, STATUS_ORDER),
    }


def _comparison(
    c: LatestComparison | None, states: dict[uuid.UUID, dict[str, int]]
) -> dict[str, Any] | None:
    if c is None:
        return None
    return {
        "comparison_id": c.comparison_id,
        "target_id": c.target_id,
        "target_name": c.target_name,
        "baseline_scan_id": c.baseline_scan_id,
        "current_scan_id": c.current_scan_id,
        "current_assessment_id": c.current_assessment_id,
        "finished_at": c.finished_at,
        "by_state": _ordered(states.get(c.comparison_id, {}), STATE_ORDER),
    }


def _report(r: LatestReport | None) -> dict[str, Any] | None:
    if r is None:
        return None
    return {
        "report_id": r.report_id,
        "number": r.number,
        "kind": r.kind,
        "title": r.title,
        "finished_at": r.finished_at,
    }


class PostureService:
    def __init__(self, repository: PostureRepository) -> None:
        self.repo = repository

    def _facts(
        self, project_ids: Sequence[uuid.UUID]
    ) -> tuple[
        list[LatestScan],
        dict[uuid.UUID, list[tuple[str, str, int]]],
        dict[uuid.UUID, LatestComparison],
        dict[uuid.UUID, dict[str, int]],
        dict[uuid.UUID, LatestReport],
        dict[uuid.UUID, LatestReport],
    ]:
        """The shared aggregates for these projects, in a fixed number of queries."""
        scans = self.repo.latest_scans(project_ids)
        per_scan: dict[uuid.UUID, list[tuple[str, str, int]]] = defaultdict(list)
        for group in self.repo.finding_counts([s.scan_id for s in scans]):
            per_scan[group.scan_id].append((group.severity, group.status, group.count))
        comparisons = {c.project_id: c for c in self.repo.latest_comparisons(project_ids)}
        states: dict[uuid.UUID, dict[str, int]] = defaultdict(dict)
        for state_group in self.repo.comparison_state_counts(
            [c.comparison_id for c in comparisons.values()]
        ):
            states[state_group.comparison_id][state_group.state] = state_group.count
        reports = {r.project_id: r for r in self.repo.latest_reports(project_ids)}
        retest_reports = {r.project_id: r for r in self.repo.latest_retest_reports(project_ids)}
        return scans, per_scan, comparisons, states, reports, retest_reports

    def project(
        self, project_id: uuid.UUID, project_name: str, role: ProjectRole
    ) -> dict[str, Any]:
        """One project's posture. The caller has project.read on it."""
        scans, per_scan, comparisons, states, reports, retest_reports = self._facts([project_id])
        latest = {s.target_id: s for s in scans}
        target_rows = self.repo.targets(project_id)
        targets = []
        for target_id, name in target_rows[:MAX_TARGETS]:
            scan = latest.get(target_id)
            targets.append(
                {
                    "target_id": target_id,
                    "target_name": name,
                    "latest_scan": None
                    if scan is None
                    else {
                        "scan_id": scan.scan_id,
                        "assessment_id": scan.assessment_id,
                        "assessment_name": scan.assessment_name,
                        "finished_at": scan.finished_at,
                    },
                    "findings": finding_counts(per_scan.get(scan.scan_id, []) if scan else []),
                }
            )
        recent = [
            {
                "scan_id": r.scan_id,
                "assessment_id": r.assessment_id,
                "assessment_name": r.assessment_name,
                "target_id": r.target_id,
                "target_name": r.target_name,
                "status": r.status,
                "created_at": r.created_at,
                "finished_at": r.finished_at,
                "analysed": r.analysed,
                # Findings exist only once the analysis completed.
                "findings_total": r.findings_total if r.analysed else None,
            }
            for r in self.repo.recent_scans(project_id)
        ]
        return {
            "project_id": project_id,
            "project_name": project_name,
            "role": role,
            "findings": finding_counts(row for s in scans for row in per_scan.get(s.scan_id, [])),
            "targets": targets,
            "targets_truncated": len(target_rows) > MAX_TARGETS,
            "latest_comparison": _comparison(comparisons.get(project_id), states),
            "latest_report": _report(reports.get(project_id)),
            "latest_retest_report": _report(retest_reports.get(project_id)),
            "recent_scans": recent,
        }

    def overview(self, user_id: uuid.UUID, *, limit: int, offset: int) -> list[dict[str, Any]]:
        """A summary of each project the user is a member of (and nothing else)."""
        projects = self.repo.visible_projects(user_id, limit=limit, offset=offset)
        ids = [p.project_id for p in projects]
        scans, per_scan, comparisons, states, reports, retest_reports = self._facts(ids)
        by_project: dict[uuid.UUID, list[LatestScan]] = defaultdict(list)
        for scan in scans:
            by_project[scan.project_id].append(scan)
        out = []
        for p in projects:
            project_id = p.project_id
            mine = by_project.get(project_id, [])
            out.append(
                {
                    "project_id": project_id,
                    "project_name": p.name,
                    "role": p.role,
                    "findings": finding_counts(
                        row for s in mine for row in per_scan.get(s.scan_id, [])
                    ),
                    "targets_with_analysed_scan": len(mine),
                    "latest_scan_finished_at": max((s.finished_at for s in mine), default=None),
                    "latest_comparison": _comparison(comparisons.get(project_id), states),
                    "latest_report": _report(reports.get(project_id)),
                    "latest_retest_report": _report(retest_reports.get(project_id)),
                }
            )
        return out
