"""Read-only aggregates for the security posture dashboard (ADR 0015).

Every method takes the projects it may look at (already authorized by the
caller) and restricts each query to them before aggregating, so nothing from
another project can be counted or named. A request issues a fixed number of
queries, whatever the number of projects or targets: DISTINCT ON for "latest",
GROUP BY for counts. Nothing here writes.
"""

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Exists, ScalarSelect, exists, func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.orm import InstrumentedAttribute, Session

from app.models import (
    AnalysisRun,
    Assessment,
    Comparison,
    ComparisonRecord,
    Finding,
    Project,
    ProjectMember,
    Report,
    RetestReport,
    Scan,
    Target,
)
from app.models.enums import (
    AnalysisStatus,
    ComparisonStatus,
    ProjectRole,
    ReportStatus,
    ScanStatus,
)

RECENT_SCANS = 10
MAX_TARGETS = 100


@dataclass(frozen=True)
class VisibleProject:
    project_id: uuid.UUID
    name: str
    role: ProjectRole


@dataclass(frozen=True)
class LatestScan:
    project_id: uuid.UUID
    target_id: uuid.UUID
    scan_id: uuid.UUID
    assessment_id: uuid.UUID
    assessment_name: str
    finished_at: datetime


@dataclass(frozen=True)
class FindingGroup:
    scan_id: uuid.UUID
    severity: str
    status: str
    count: int


@dataclass(frozen=True)
class LatestComparison:
    project_id: uuid.UUID
    comparison_id: uuid.UUID
    target_id: uuid.UUID
    target_name: str
    baseline_scan_id: uuid.UUID
    current_scan_id: uuid.UUID
    current_assessment_id: uuid.UUID
    finished_at: datetime


@dataclass(frozen=True)
class StateGroup:
    comparison_id: uuid.UUID
    state: str
    count: int


@dataclass(frozen=True)
class LatestReport:
    project_id: uuid.UUID
    report_id: uuid.UUID
    number: int
    kind: str
    title: str
    finished_at: datetime


@dataclass(frozen=True)
class RecentScanRow:
    scan_id: uuid.UUID
    assessment_id: uuid.UUID
    assessment_name: str
    target_id: uuid.UUID
    target_name: str
    status: ScanStatus
    created_at: datetime
    finished_at: datetime | None
    analysed: bool
    findings_total: int


def _finished(value: datetime | None) -> datetime:
    """Completed rows always have finished_at (finished_iff_terminal checks)."""
    if value is None:  # pragma: no cover  # guaranteed by the database
        raise ValueError("a completed row without finished_at")
    return value


def _analysed(scan_id: InstrumentedAttribute[uuid.UUID]) -> Exists:
    """The scan has a completed analysis run."""
    return exists().where(
        AnalysisRun.scan_id == scan_id, AnalysisRun.status == AnalysisStatus.COMPLETED
    )


class PostureRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    # --- which projects -----------------------------------------------------------------------

    def visible_projects(
        self, user_id: uuid.UUID, *, limit: int, offset: int
    ) -> list[VisibleProject]:
        """The caller's projects and their role in each, in the order of
        GET /projects. Membership only: a global role grants nothing here."""
        stmt = (
            select(Project.id, Project.name, ProjectMember.role)
            .join(ProjectMember, ProjectMember.project_id == Project.id)
            .where(ProjectMember.user_id == user_id)
            .order_by(Project.created_at, Project.id)
            .limit(limit)
            .offset(offset)
        )
        return [
            VisibleProject(pid, name, ProjectRole(role))
            for pid, name, role in self.session.execute(stmt)
        ]

    def targets(self, project_id: uuid.UUID) -> list[tuple[uuid.UUID, str]]:
        """Up to MAX_TARGETS + 1 targets (the extra one only signals truncation)."""
        stmt = (
            select(Target.id, Target.name)
            .where(Target.project_id == project_id)
            .order_by(Target.name, Target.id)
            .limit(MAX_TARGETS + 1)
        )
        return [(tid, name) for tid, name in self.session.execute(stmt)]

    # --- latest analysed scans and their findings -----------------------------------------------

    def latest_scans(self, project_ids: Sequence[uuid.UUID]) -> list[LatestScan]:
        """Per target of these projects: the latest completed scan with a
        completed analysis, by finished_at DESC, id DESC."""
        if not project_ids:
            return []
        stmt = (
            select(
                Target.project_id,
                Scan.target_id,
                Scan.id,
                Scan.assessment_id,
                Assessment.name,
                Scan.finished_at,
            )
            .join(Target, Target.id == Scan.target_id)
            .join(Assessment, Assessment.id == Scan.assessment_id)
            .where(
                Target.project_id.in_(project_ids),
                Scan.status == ScanStatus.COMPLETED,
                _analysed(Scan.id),
            )
            .ext(distinct_on(Scan.target_id))
            .order_by(Scan.target_id, Scan.finished_at.desc(), Scan.id.desc())
        )
        return [
            LatestScan(pid, tid, sid, aid, name, _finished(finished))
            for pid, tid, sid, aid, name, finished in self.session.execute(stmt)
        ]

    def finding_counts(self, scan_ids: Sequence[uuid.UUID]) -> list[FindingGroup]:
        """(scan, severity, triage status, count) of the persisted findings."""
        if not scan_ids:
            return []
        stmt = (
            select(Finding.scan_id, Finding.severity, Finding.status, func.count())
            .where(Finding.scan_id.in_(scan_ids))
            .group_by(Finding.scan_id, Finding.severity, Finding.status)
        )
        return [
            FindingGroup(sid, str(severity), str(status), int(count))
            for sid, severity, status, count in self.session.execute(stmt)
        ]

    # --- retests ------------------------------------------------------------------------------

    def latest_comparisons(self, project_ids: Sequence[uuid.UUID]) -> list[LatestComparison]:
        """Per project: the latest completed comparison, by finished_at DESC, id DESC."""
        if not project_ids:
            return []
        stmt = (
            select(
                Target.project_id,
                Comparison.id,
                Comparison.target_id,
                Target.name,
                Comparison.baseline_scan_id,
                Comparison.current_scan_id,
                Comparison.current_assessment_id,
                Comparison.finished_at,
            )
            .join(Target, Target.id == Comparison.target_id)
            .where(
                Target.project_id.in_(project_ids),
                Comparison.status == ComparisonStatus.COMPLETED,
            )
            .ext(distinct_on(Target.project_id))
            .order_by(Target.project_id, Comparison.finished_at.desc(), Comparison.id.desc())
        )
        return [
            LatestComparison(pid, cid, tid, tname, base, cur, cur_assessment, _finished(fin))
            for pid, cid, tid, tname, base, cur, cur_assessment, fin in self.session.execute(stmt)
        ]

    def comparison_state_counts(self, comparison_ids: Sequence[uuid.UUID]) -> list[StateGroup]:
        """(comparison, state, count) of the persisted comparison records."""
        if not comparison_ids:
            return []
        stmt = (
            select(ComparisonRecord.comparison_id, ComparisonRecord.state, func.count())
            .where(ComparisonRecord.comparison_id.in_(comparison_ids))
            .group_by(ComparisonRecord.comparison_id, ComparisonRecord.state)
        )
        return [
            StateGroup(cid, str(state), int(count))
            for cid, state, count in self.session.execute(stmt)
        ]

    # --- reports ------------------------------------------------------------------------------

    def _latest(
        self, model: type[Report] | type[RetestReport], project_ids: Sequence[uuid.UUID]
    ) -> list[LatestReport]:
        if not project_ids:
            return []
        stmt = (
            select(
                Target.project_id,
                model.id,
                model.number,
                model.kind,
                model.title,
                model.finished_at,
            )
            .join(Target, Target.id == model.target_id)
            .where(Target.project_id.in_(project_ids), model.status == ReportStatus.COMPLETED)
            .ext(distinct_on(Target.project_id))
            .order_by(Target.project_id, model.finished_at.desc(), model.id.desc())
        )
        return [
            LatestReport(pid, rid, int(number), str(kind), title, _finished(finished))
            for pid, rid, number, kind, title, finished in self.session.execute(stmt)
        ]

    def latest_reports(self, project_ids: Sequence[uuid.UUID]) -> list[LatestReport]:
        return self._latest(Report, project_ids)

    def latest_retest_reports(self, project_ids: Sequence[uuid.UUID]) -> list[LatestReport]:
        return self._latest(RetestReport, project_ids)

    # --- history ------------------------------------------------------------------------------

    def recent_scans(self, project_id: uuid.UUID) -> list[RecentScanRow]:
        """The project's RECENT_SCANS most recent scans (any status), newest
        first, with the number of persisted findings of each."""
        findings: ScalarSelect[int] = (
            select(func.count()).where(Finding.scan_id == Scan.id).correlate(Scan).scalar_subquery()
        )
        stmt = (
            select(
                Scan.id,
                Scan.assessment_id,
                Assessment.name,
                Scan.target_id,
                Target.name,
                Scan.status,
                Scan.created_at,
                Scan.finished_at,
                _analysed(Scan.id).label("analysed"),
                findings.label("findings"),
            )
            .join(Target, Target.id == Scan.target_id)
            .join(Assessment, Assessment.id == Scan.assessment_id)
            .where(Target.project_id == project_id)
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .limit(RECENT_SCANS)
        )
        return [
            RecentScanRow(
                row[0], row[1], row[2], row[3], row[4], ScanStatus(row[5]), row[6], row[7],
                bool(row[8]), int(row[9]),
            )
            for row in self.session.execute(stmt)
        ]  # fmt: skip
