import uuid
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, text, tuple_, update
from sqlalchemy.dialects.postgresql import insert

from app.models import (
    AnalysisRun,
    Evidence,
    Finding,
    FindingEvidence,
    FindingStatusChange,
    Report,
    ReportArtifact,
    ReportEvidence,
    ReportFinding,
    RuleVersion,
)
from app.models.enums import AnalysisStatus, ReportStatus
from app.models.report import report_number_seq
from app.repositories.base import SqlRepository

ARTIFACT_METADATA = (
    ReportArtifact.report_id,
    ReportArtifact.format,
    ReportArtifact.media_type,
    ReportArtifact.size_bytes,
    ReportArtifact.sha256,
    ReportArtifact.renderer,
    ReportArtifact.created_at,
)


class ReportRepository(SqlRepository[Report]):
    model = Report

    # --- creation -----------------------------------------------------------------------

    def next_number(self) -> int:
        number = self.session.scalar(select(report_number_seq.next_value()))
        assert number is not None  # noqa: S101  # a sequence always yields a value
        return int(number)

    def add_links(
        self,
        report_id: uuid.UUID,
        scan_id: uuid.UUID,
        findings: Iterable[tuple[uuid.UUID, str]],
        evidence_ids: Iterable[uuid.UUID],
    ) -> None:
        finding_rows = [
            {"report_id": report_id, "scan_id": scan_id, "finding_id": f, "status_at_report": s}
            for f, s in findings
        ]
        evidence_rows = [
            {"report_id": report_id, "scan_id": scan_id, "evidence_id": e} for e in evidence_ids
        ]
        if finding_rows:
            self.session.execute(insert(ReportFinding).values(finding_rows))
        if evidence_rows:
            self.session.execute(insert(ReportEvidence).values(evidence_rows))

    # --- snapshot sources (read-only) ----------------------------------------------------

    def latest_completed_run(self, scan_id: uuid.UUID) -> AnalysisRun | None:
        stmt = (
            select(AnalysisRun)
            .where(AnalysisRun.scan_id == scan_id, AnalysisRun.status == AnalysisStatus.COMPLETED)
            .order_by(AnalysisRun.finished_at.desc(), AnalysisRun.id)
            .limit(1)
        )
        return self.session.scalars(stmt).one_or_none()

    def findings_for_run(self, scan_id: uuid.UUID, run_id: uuid.UUID) -> Sequence[Finding]:
        """The run's findings, share-locked until the transaction ends: triage
        (which locks a finding FOR UPDATE) waits, so the snapshot sees each
        finding and its history in one consistent state."""
        stmt = (
            select(Finding)
            .where(Finding.scan_id == scan_id, Finding.analysis_run_id == run_id)
            .order_by(Finding.id)
            .with_for_update(read=True)
            .execution_options(populate_existing=True)
        )
        return self.session.scalars(stmt).all()

    def rule_versions(self, keys: Iterable[tuple[str, int]]) -> dict[tuple[str, int], RuleVersion]:
        wanted = set(keys)
        if not wanted:
            return {}
        stmt = select(RuleVersion).where(
            tuple_(RuleVersion.rule_id, RuleVersion.version).in_(sorted(wanted))
        )
        return {(r.rule_id, r.version): r for r in self.session.scalars(stmt)}

    def evidence_by_ids(
        self, scan_id: uuid.UUID, evidence_ids: Iterable[uuid.UUID]
    ) -> Sequence[Evidence]:
        ids = sorted(set(evidence_ids))
        if not ids:
            return []
        stmt = select(Evidence).where(Evidence.scan_id == scan_id, Evidence.id.in_(ids))
        return self.session.scalars(stmt).all()

    def evidence_links(self, finding_ids: Iterable[uuid.UUID]) -> dict[uuid.UUID, list[uuid.UUID]]:
        ids = sorted(set(finding_ids))
        links: dict[uuid.UUID, list[uuid.UUID]] = {i: [] for i in ids}
        if not ids:
            return links
        stmt = select(FindingEvidence.finding_id, FindingEvidence.evidence_id).where(
            FindingEvidence.finding_id.in_(ids)
        )
        for finding_id, evidence_id in self.session.execute(stmt):
            links[finding_id].append(evidence_id)
        return links

    def status_changes(self, finding_ids: Iterable[uuid.UUID]) -> Sequence[FindingStatusChange]:
        ids = sorted(set(finding_ids))
        if not ids:
            return []
        stmt = (
            select(FindingStatusChange)
            .where(FindingStatusChange.finding_id.in_(ids))
            .order_by(FindingStatusChange.changed_at, FindingStatusChange.id)
        )
        return self.session.scalars(stmt).all()

    # --- reads ---------------------------------------------------------------------------

    def list_for_assessment(
        self, assessment_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[Report]:
        stmt = (
            select(Report)
            .where(Report.assessment_id == assessment_id)
            .order_by(Report.created_at.desc(), Report.number.desc())
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()

    def artifact_metadata(self, report_ids: Iterable[uuid.UUID]) -> Sequence[Any]:
        ids = sorted(set(report_ids))
        if not ids:
            return []
        stmt = (
            select(*ARTIFACT_METADATA)
            .where(ReportArtifact.report_id.in_(ids))
            .order_by(ReportArtifact.report_id, ReportArtifact.format)
        )
        return self.session.execute(stmt).all()

    def artifact(self, report_id: uuid.UUID, fmt: str) -> ReportArtifact | None:
        return self.session.get(ReportArtifact, (report_id, fmt))

    # --- worker --------------------------------------------------------------------------

    def queued_ids(self, limit: int) -> list[uuid.UUID]:
        stmt = (
            select(Report.id)
            .where(Report.status == ReportStatus.QUEUED)
            .order_by(Report.created_at, Report.number)
            .limit(limit)
        )
        return list(self.session.scalars(stmt).all())

    def get_for_update(self, report_id: uuid.UUID, *, skip_locked: bool = False) -> Report | None:
        stmt = (
            select(Report)
            .where(Report.id == report_id)
            .with_for_update(skip_locked=skip_locked)
            .execution_options(populate_existing=True)
        )
        return self.session.scalars(stmt).one_or_none()

    def add_artifact(self, artifact: ReportArtifact) -> None:
        self.session.add(artifact)
        self.session.flush()

    def reap_stale(self, stale_after_seconds: float, now: datetime) -> list[uuid.UUID]:
        """Fail reports whose worker stopped while generating them. Judged by
        the database clock; rows locked by a live finalize are skipped."""
        stale = (
            select(Report.id)
            .where(
                Report.status == ReportStatus.GENERATING,
                Report.claimed_at < func.now() - text("make_interval(secs => :stale)"),
            )
            .with_for_update(skip_locked=True)
            .scalar_subquery()
        )
        stmt = (
            update(Report)
            .where(Report.id.in_(stale))
            .values(status=ReportStatus.FAILED, error_code="worker_lost", finished_at=now)
            .returning(Report.id)
        )
        return list(self.session.scalars(stmt, {"stale": stale_after_seconds}).all())
