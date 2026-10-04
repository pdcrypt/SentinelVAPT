import uuid
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert

from app.models import (
    Comparison,
    ComparisonCoverageEvidence,
    ComparisonRecord,
    Evidence,
    Finding,
    FindingEvidence,
    RetestReport,
    RetestReportArtifact,
    RetestReportEvidence,
)
from app.models.enums import ReportStatus
from app.models.retest_report import retest_report_number_seq
from app.repositories.base import SqlRepository

ARTIFACT_METADATA = (
    RetestReportArtifact.report_id,
    RetestReportArtifact.format,
    RetestReportArtifact.media_type,
    RetestReportArtifact.size_bytes,
    RetestReportArtifact.sha256,
    RetestReportArtifact.renderer,
    RetestReportArtifact.created_at,
)


class RetestReportRepository(SqlRepository[RetestReport]):
    model = RetestReport

    # --- creation -----------------------------------------------------------------------

    def next_number(self) -> int:
        number = self.session.scalar(select(retest_report_number_seq.next_value()))
        assert number is not None  # noqa: S101  # a sequence always yields a value
        return int(number)

    def insert_if_new(self, values: dict[str, Any]) -> uuid.UUID | None:
        """Insert unless an identical, non-failed report exists (same comparison,
        kind and content digest); returns the new id or None."""
        new_id: uuid.UUID | None = self.session.scalar(
            insert(RetestReport)
            .values(**values)
            .on_conflict_do_nothing(
                index_elements=["comparison_id", "kind", "content_sha256"],
                index_where=text("status <> 'failed'"),
            )
            .returning(RetestReport.id)
        )
        return new_id

    def identical(
        self, comparison_id: uuid.UUID, kind: str, content_sha256: str
    ) -> RetestReport | None:
        stmt = select(RetestReport).where(
            RetestReport.comparison_id == comparison_id,
            RetestReport.kind == kind,
            RetestReport.content_sha256 == content_sha256,
            RetestReport.status != ReportStatus.FAILED,
        )
        return self.session.scalars(stmt).one_or_none()

    def add_evidence_links(self, rows: Sequence[dict[str, Any]]) -> None:
        if rows:
            self.session.execute(insert(RetestReportEvidence).values(list(rows)))

    # --- snapshot sources (read-only) ----------------------------------------------------

    def records(self, comparison_id: uuid.UUID) -> Sequence[ComparisonRecord]:
        stmt = (
            select(ComparisonRecord)
            .where(ComparisonRecord.comparison_id == comparison_id)
            .order_by(ComparisonRecord.fingerprint)
        )
        return self.session.scalars(stmt).all()

    def coverage(self, comparison_id: uuid.UUID) -> dict[str, list[uuid.UUID]]:
        grouped: dict[str, list[uuid.UUID]] = {}
        stmt = (
            select(ComparisonCoverageEvidence.fingerprint, ComparisonCoverageEvidence.evidence_id)
            .where(ComparisonCoverageEvidence.comparison_id == comparison_id)
            .order_by(
                ComparisonCoverageEvidence.fingerprint, ComparisonCoverageEvidence.evidence_id
            )
        )
        for fingerprint, evidence_id in self.session.execute(stmt):
            grouped.setdefault(fingerprint, []).append(evidence_id)
        return grouped

    def findings_share_locked(self, finding_ids: Iterable[uuid.UUID]) -> dict[uuid.UUID, Finding]:
        """The findings, share-locked until the transaction ends, so a triage
        (FOR UPDATE) cannot interleave with reading their current status."""
        ids = sorted(set(finding_ids))
        if not ids:
            return {}
        stmt = (
            select(Finding)
            .where(Finding.id.in_(ids))
            .order_by(Finding.id)
            .with_for_update(read=True)
            .execution_options(populate_existing=True)
        )
        return {f.id: f for f in self.session.scalars(stmt)}

    def finding_evidence(
        self, finding_ids: Iterable[uuid.UUID]
    ) -> dict[uuid.UUID, list[uuid.UUID]]:
        ids = sorted(set(finding_ids))
        grouped: dict[uuid.UUID, list[uuid.UUID]] = {i: [] for i in ids}
        if not ids:
            return grouped
        stmt = (
            select(FindingEvidence.finding_id, FindingEvidence.evidence_id)
            .where(FindingEvidence.finding_id.in_(ids))
            .order_by(FindingEvidence.finding_id, FindingEvidence.evidence_id)
        )
        for finding_id, evidence_id in self.session.execute(stmt):
            grouped[finding_id].append(evidence_id)
        return grouped

    def evidence(self, scan_id: uuid.UUID, evidence_ids: Iterable[uuid.UUID]) -> Sequence[Evidence]:
        ids = sorted(set(evidence_ids))
        if not ids:
            return []
        stmt = select(Evidence).where(Evidence.scan_id == scan_id, Evidence.id.in_(ids))
        return self.session.scalars(stmt).all()

    def comparison_for_scan(self, scan_id: uuid.UUID, policy_version: str) -> Comparison | None:
        stmt = select(Comparison).where(
            Comparison.current_scan_id == scan_id, Comparison.policy_version == policy_version
        )
        return self.session.scalars(stmt).one_or_none()

    def summary_of(self, comparison_id: uuid.UUID) -> dict[str, int]:
        stmt = (
            select(ComparisonRecord.state, func.count())
            .where(ComparisonRecord.comparison_id == comparison_id)
            .group_by(ComparisonRecord.state)
        )
        return {str(state): int(count) for state, count in self.session.execute(stmt)}

    def record_states(self, comparison_id: uuid.UUID) -> dict[str, str]:
        stmt = select(ComparisonRecord.fingerprint, ComparisonRecord.state).where(
            ComparisonRecord.comparison_id == comparison_id
        )
        return {fp: str(state) for fp, state in self.session.execute(stmt)}

    # --- reads ---------------------------------------------------------------------------

    def list_for_assessment(
        self, assessment_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[RetestReport]:
        stmt = (
            select(RetestReport)
            .where(RetestReport.current_assessment_id == assessment_id)
            .order_by(RetestReport.created_at.desc(), RetestReport.number.desc())
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
            .where(RetestReportArtifact.report_id.in_(ids))
            .order_by(RetestReportArtifact.report_id, RetestReportArtifact.format)
        )
        return self.session.execute(stmt).all()

    def artifact(self, report_id: uuid.UUID, fmt: str) -> RetestReportArtifact | None:
        return self.session.get(RetestReportArtifact, (report_id, fmt))

    # --- worker --------------------------------------------------------------------------

    def queued_ids(self, limit: int) -> list[uuid.UUID]:
        stmt = (
            select(RetestReport.id)
            .where(RetestReport.status == ReportStatus.QUEUED)
            .order_by(RetestReport.created_at, RetestReport.number)
            .limit(limit)
        )
        return list(self.session.scalars(stmt).all())

    def get_for_update(
        self, report_id: uuid.UUID, *, skip_locked: bool = False
    ) -> RetestReport | None:
        stmt = (
            select(RetestReport)
            .where(RetestReport.id == report_id)
            .with_for_update(skip_locked=skip_locked)
            .execution_options(populate_existing=True)
        )
        return self.session.scalars(stmt).one_or_none()

    def add_artifact(self, artifact: RetestReportArtifact) -> None:
        self.session.add(artifact)
        self.session.flush()

    def reap_stale(self, stale_after_seconds: float, now: datetime) -> list[uuid.UUID]:
        stale = (
            select(RetestReport.id)
            .where(
                RetestReport.status == ReportStatus.GENERATING,
                RetestReport.claimed_at < func.now() - text("make_interval(secs => :stale)"),
            )
            .with_for_update(skip_locked=True)
            .scalar_subquery()
        )
        stmt = (
            update(RetestReport)
            .where(RetestReport.id.in_(stale))
            .values(status=ReportStatus.FAILED, error_code="worker_lost", finished_at=now)
            .returning(RetestReport.id)
        )
        return list(self.session.scalars(stmt, {"stale": stale_after_seconds}).all())
