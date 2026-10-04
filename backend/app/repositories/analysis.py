import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from app.models import (
    AnalysisRun,
    Asset,
    Endpoint,
    EndpointCookie,
    Evidence,
    Finding,
    FindingEvidence,
    FindingStatusChange,
    RuleVersion,
    ScanLog,
)
from app.models.enums import AnalysisStatus
from app.repositories.base import SqlRepository


class AnalysisRepository(SqlRepository[AnalysisRun]):
    model = AnalysisRun

    # --- runs -------------------------------------------------------------------------

    def queue_run(self, scan_id: uuid.UUID, ruleset_version: str) -> None:
        """Idempotent: a scan is analysed once per ruleset version."""
        stmt = (
            insert(AnalysisRun)
            .values(id=uuid.uuid4(), scan_id=scan_id, ruleset_version=ruleset_version)
            .on_conflict_do_nothing(index_elements=["scan_id", "ruleset_version"])
        )
        self.session.execute(stmt)

    def queued_run_ids(self, limit: int) -> list[uuid.UUID]:
        stmt = (
            select(AnalysisRun.id)
            .where(AnalysisRun.status == AnalysisStatus.QUEUED)
            .order_by(AnalysisRun.created_at, AnalysisRun.id)
            .limit(limit)
        )
        return list(self.session.scalars(stmt).all())

    def get_run_for_update(self, run_id: uuid.UUID, *, skip_locked: bool) -> AnalysisRun | None:
        stmt = (
            select(AnalysisRun)
            .where(AnalysisRun.id == run_id)
            .with_for_update(skip_locked=skip_locked)
            .execution_options(populate_existing=True)
        )
        return self.session.scalars(stmt).one_or_none()

    def runs_for_scan(self, scan_id: uuid.UUID) -> Sequence[AnalysisRun]:
        stmt = (
            select(AnalysisRun)
            .where(AnalysisRun.scan_id == scan_id)
            .order_by(AnalysisRun.created_at, AnalysisRun.id)
        )
        return self.session.scalars(stmt).all()

    # --- observations (read-only) -------------------------------------------------------

    def assets(self, scan_id: uuid.UUID) -> Sequence[Asset]:
        return self.session.scalars(
            select(Asset).where(Asset.scan_id == scan_id).order_by(Asset.id)
        ).all()

    def endpoints(self, scan_id: uuid.UUID) -> Sequence[Endpoint]:
        return self.session.scalars(
            select(Endpoint).where(Endpoint.scan_id == scan_id).order_by(Endpoint.id)
        ).all()

    def cookies(self, scan_id: uuid.UUID) -> Sequence[EndpointCookie]:
        stmt = (
            select(EndpointCookie)
            .join(Endpoint, Endpoint.id == EndpointCookie.endpoint_id)
            .where(Endpoint.scan_id == scan_id)
            .order_by(EndpointCookie.id)
        )
        return self.session.scalars(stmt).all()

    def evidence(self, scan_id: uuid.UUID) -> Sequence[Evidence]:
        return self.session.scalars(
            select(Evidence).where(Evidence.scan_id == scan_id).order_by(Evidence.id)
        ).all()

    def logs(self, scan_id: uuid.UUID) -> Sequence[ScanLog]:
        return self.session.scalars(
            select(ScanLog).where(ScanLog.scan_id == scan_id).order_by(ScanLog.sequence)
        ).all()

    # --- rule versions ------------------------------------------------------------------

    def insert_rule_version(
        self, rule_id: str, version: int, metadata_hash: str, metadata: dict[str, Any]
    ) -> str:
        """Insert once; return the stored hash (which may differ from the given
        one if the row already existed)."""
        self.session.execute(
            insert(RuleVersion)
            .values(
                rule_id=rule_id,
                version=version,
                metadata_hash=metadata_hash,
                rule_metadata=metadata,
            )
            .on_conflict_do_nothing(index_elements=["rule_id", "version"])
        )
        stored = self.session.scalar(
            select(RuleVersion.metadata_hash).where(
                RuleVersion.rule_id == rule_id, RuleVersion.version == version
            )
        )
        assert stored is not None  # noqa: S101  # inserted or already present above
        return stored

    def get_rule_version(self, rule_id: str, version: int) -> RuleVersion | None:
        return self.session.get(RuleVersion, (rule_id, version))

    # --- findings -----------------------------------------------------------------------

    def insert_finding(self, values: dict[str, Any]) -> uuid.UUID:
        """Insert unless (scan_id, fingerprint) exists; return the row's id.
        An existing finding (and its triage) is never overwritten."""
        inserted: uuid.UUID | None = self.session.scalar(
            insert(Finding)
            .values(id=uuid.uuid4(), **values)
            .on_conflict_do_nothing(index_elements=["scan_id", "fingerprint"])
            .returning(Finding.id)
        )
        if inserted is not None:
            return inserted
        existing = self.session.scalar(
            select(Finding.id).where(
                Finding.scan_id == values["scan_id"], Finding.fingerprint == values["fingerprint"]
            )
        )
        assert existing is not None  # noqa: S101  # the conflict means it exists
        return existing

    def link_evidence(
        self, finding_id: uuid.UUID, scan_id: uuid.UUID, evidence_ids: Sequence[uuid.UUID]
    ) -> None:
        if not evidence_ids:
            return
        self.session.execute(
            insert(FindingEvidence)
            .values(
                [
                    {"finding_id": finding_id, "evidence_id": e, "scan_id": scan_id}
                    for e in evidence_ids
                ]
            )
            .on_conflict_do_nothing()
        )

    def get_finding(self, finding_id: uuid.UUID) -> Finding | None:
        return self.session.get(Finding, finding_id)

    def get_finding_for_update(self, finding_id: uuid.UUID) -> Finding | None:
        stmt = (
            select(Finding)
            .where(Finding.id == finding_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return self.session.scalars(stmt).one_or_none()

    def list_findings(
        self, scan_id: uuid.UUID, filters: dict[str, str], *, limit: int, offset: int
    ) -> Sequence[Finding]:
        stmt = select(Finding).where(Finding.scan_id == scan_id)
        for column, value in filters.items():
            stmt = stmt.where(getattr(Finding, column) == value)
        stmt = stmt.order_by(Finding.rule_id, Finding.fingerprint).limit(limit).offset(offset)
        return self.session.scalars(stmt).all()

    def count_by(
        self,
        column: str,
        *,
        scan_id: uuid.UUID | None = None,
        assessment_id: uuid.UUID | None = None,
    ) -> dict[str, int]:
        col = getattr(Finding, column)
        stmt = select(col, func.count()).group_by(col)
        if scan_id is not None:
            stmt = stmt.where(Finding.scan_id == scan_id)
        if assessment_id is not None:
            stmt = stmt.where(Finding.assessment_id == assessment_id)
        return {str(key): int(count) for key, count in self.session.execute(stmt)}

    def finding_evidence(self, finding_id: uuid.UUID) -> Sequence[Evidence]:
        stmt = (
            select(Evidence)
            .join(
                FindingEvidence,
                (FindingEvidence.evidence_id == Evidence.id)
                & (FindingEvidence.scan_id == Evidence.scan_id),
            )
            .where(FindingEvidence.finding_id == finding_id)
            .order_by(Evidence.url, Evidence.method, Evidence.id)
        )
        return self.session.scalars(stmt).all()

    def history(self, finding_id: uuid.UUID) -> Sequence[FindingStatusChange]:
        stmt = (
            select(FindingStatusChange)
            .where(FindingStatusChange.finding_id == finding_id)
            .order_by(FindingStatusChange.changed_at, FindingStatusChange.id)
        )
        return self.session.scalars(stmt).all()

    def add_status_change(self, change: FindingStatusChange) -> None:
        self.session.add(change)
        self.session.flush()
