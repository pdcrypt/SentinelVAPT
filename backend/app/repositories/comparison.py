import uuid
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from app.models import (
    AnalysisRun,
    Assessment,
    Comparison,
    ComparisonCoverageEvidence,
    ComparisonRecord,
    Finding,
    FindingEvidence,
    Scan,
)
from app.models.enums import AnalysisStatus, AssessmentStatus, ComparisonStatus, ScanStatus
from app.repositories.base import SqlRepository


class ComparisonRepository(SqlRepository[Comparison]):
    model = Comparison

    # --- retests -----------------------------------------------------------------------

    def live_retest(self, parent_id: uuid.UUID) -> Assessment | None:
        stmt = select(Assessment).where(
            Assessment.retest_of_assessment_id == parent_id,
            Assessment.status != AssessmentStatus.CANCELLED,
        )
        return self.session.scalars(stmt).first()

    def retests_of(self, parent_id: uuid.UUID) -> Sequence[Assessment]:
        stmt = (
            select(Assessment)
            .where(Assessment.retest_of_assessment_id == parent_id)
            .order_by(Assessment.created_at, Assessment.id)
        )
        return self.session.scalars(stmt).all()

    def completed_run(
        self, scan_id: uuid.UUID, *, prefer_ruleset: str | None = None
    ) -> AnalysisRun | None:
        """The scan's completed analysis run: the one for `prefer_ruleset` if
        there is one, otherwise the most recently finished."""
        stmt = (
            select(AnalysisRun)
            .where(AnalysisRun.scan_id == scan_id, AnalysisRun.status == AnalysisStatus.COMPLETED)
            .order_by(AnalysisRun.finished_at.desc(), AnalysisRun.id)
        )
        runs = self.session.scalars(stmt).all()
        preferred = [r for r in runs if r.ruleset_version == prefer_ruleset]
        candidates = preferred or list(runs)
        return candidates[0] if candidates else None

    def latest_analysed_scan(self, assessment_id: uuid.UUID) -> Scan | None:
        stmt = (
            select(Scan)
            .where(
                Scan.assessment_id == assessment_id,
                Scan.status == ScanStatus.COMPLETED,
                select(AnalysisRun.id)
                .where(
                    AnalysisRun.scan_id == Scan.id,
                    AnalysisRun.status == AnalysisStatus.COMPLETED,
                )
                .exists(),
            )
            .order_by(Scan.finished_at.desc(), Scan.id)
            .limit(1)
        )
        return self.session.scalars(stmt).one_or_none()

    # --- comparisons ---------------------------------------------------------------------

    def queue(self, values: Mapping[str, Any]) -> uuid.UUID | None:
        """Insert a queued comparison unless one exists for (current scan,
        policy); returns the new id, or None if it already existed."""
        new_id: uuid.UUID | None = self.session.scalar(
            insert(Comparison)
            .values(id=uuid.uuid4(), **values)
            .on_conflict_do_nothing(index_elements=["current_scan_id", "policy_version"])
            .returning(Comparison.id)
        )
        return new_id

    def for_scan(self, scan_id: uuid.UUID, policy_version: str) -> Comparison | None:
        stmt = select(Comparison).where(
            Comparison.current_scan_id == scan_id, Comparison.policy_version == policy_version
        )
        return self.session.scalars(stmt).one_or_none()

    def list_for_assessment(self, assessment_id: uuid.UUID) -> Sequence[Comparison]:
        stmt = (
            select(Comparison)
            .where(Comparison.current_assessment_id == assessment_id)
            .order_by(Comparison.created_at, Comparison.id)
        )
        return self.session.scalars(stmt).all()

    def queued_ids(self, limit: int) -> list[uuid.UUID]:
        stmt = (
            select(Comparison.id)
            .where(Comparison.status == ComparisonStatus.QUEUED)
            .order_by(Comparison.created_at, Comparison.id)
            .limit(limit)
        )
        return list(self.session.scalars(stmt).all())

    def get_for_update(self, comparison_id: uuid.UUID, *, skip_locked: bool) -> Comparison | None:
        stmt = (
            select(Comparison)
            .where(Comparison.id == comparison_id)
            .with_for_update(skip_locked=skip_locked)
            .execution_options(populate_existing=True)
        )
        return self.session.scalars(stmt).one_or_none()

    # --- inputs (read-only) -----------------------------------------------------------------

    def findings_for_run(self, scan_id: uuid.UUID, run_id: uuid.UUID) -> Sequence[Finding]:
        """The run's findings, share-locked until the transaction ends, so a
        triage (which locks a finding FOR UPDATE) cannot interleave with the
        comparison reading them."""
        stmt = (
            select(Finding)
            .where(Finding.scan_id == scan_id, Finding.analysis_run_id == run_id)
            .order_by(Finding.id)
            .with_for_update(read=True)
            .execution_options(populate_existing=True)
        )
        return self.session.scalars(stmt).all()

    def chain_history(
        self, comparison_id: uuid.UUID | None, max_depth: int = 1000
    ) -> dict[str, str]:
        """For each fingerprint, the state of its most recent record in the
        chain of comparisons ending with `comparison_id`."""
        history: dict[str, str] = {}
        depth = 0
        while comparison_id is not None and depth < max_depth:
            for fingerprint, state in self.session.execute(
                select(ComparisonRecord.fingerprint, ComparisonRecord.state).where(
                    ComparisonRecord.comparison_id == comparison_id
                )
            ):
                history.setdefault(fingerprint, str(state))
            comparison_id = self.session.scalar(
                select(Comparison.previous_comparison_id).where(Comparison.id == comparison_id)
            )
            depth += 1
        return history

    # --- results -----------------------------------------------------------------------------

    def add_records(self, rows: Sequence[Mapping[str, Any]]) -> None:
        if rows:
            self.session.execute(insert(ComparisonRecord).values(list(rows)))

    def add_coverage(self, rows: Sequence[Mapping[str, Any]]) -> None:
        if rows:
            self.session.execute(insert(ComparisonCoverageEvidence).values(list(rows)))

    def records(
        self,
        comparison_id: uuid.UUID,
        *,
        state: str | None = None,
        rule_id: str | None = None,
        limit: int,
        offset: int,
    ) -> Sequence[ComparisonRecord]:
        stmt = select(ComparisonRecord).where(ComparisonRecord.comparison_id == comparison_id)
        if state is not None:
            stmt = stmt.where(ComparisonRecord.state == state)
        if rule_id is not None:
            stmt = stmt.where(ComparisonRecord.rule_id == rule_id)
        stmt = stmt.order_by(ComparisonRecord.fingerprint).limit(limit).offset(offset)
        return self.session.scalars(stmt).all()

    def record(self, comparison_id: uuid.UUID, fingerprint: str) -> ComparisonRecord | None:
        return self.session.get(ComparisonRecord, (comparison_id, fingerprint))

    def coverage_evidence(
        self, comparison_id: uuid.UUID, fingerprints: Iterable[str]
    ) -> dict[str, list[uuid.UUID]]:
        fps = sorted(set(fingerprints))
        grouped: dict[str, list[uuid.UUID]] = {fp: [] for fp in fps}
        if not fps:
            return grouped
        stmt = (
            select(ComparisonCoverageEvidence.fingerprint, ComparisonCoverageEvidence.evidence_id)
            .where(
                ComparisonCoverageEvidence.comparison_id == comparison_id,
                ComparisonCoverageEvidence.fingerprint.in_(fps),
            )
            .order_by(
                ComparisonCoverageEvidence.fingerprint, ComparisonCoverageEvidence.evidence_id
            )
        )
        for fingerprint, evidence_id in self.session.execute(stmt):
            grouped[fingerprint].append(evidence_id)
        return grouped

    def finding_evidence(
        self, finding_ids: Iterable[uuid.UUID]
    ) -> dict[uuid.UUID, list[uuid.UUID]]:
        ids = sorted({i for i in finding_ids if i is not None})
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
