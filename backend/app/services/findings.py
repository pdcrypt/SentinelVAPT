import uuid
from collections.abc import Sequence
from typing import Any

from app.core.clock import Clock
from app.core.errors import InvalidStateTransitionError, NotFoundError
from app.models import AnalysisRun, Evidence, Finding, FindingStatusChange
from app.models.enums import FindingStatus
from app.repositories import AnalysisRepository, AssessmentRepository, ScanRepository
from app.services.base import UnitOfWork

_SUMMARY_COLUMNS = {
    "by_severity": "severity",
    "by_status": "status",
    "by_confidence": "confidence",
    "by_detection_type": "detection_type",
    "by_category": "category",
}


class FindingService:
    """Reads and triage of rule findings. Findings are only created by the
    analysis worker; there is no manual creation or re-analysis in Phase 4."""

    def __init__(
        self,
        analysis: AnalysisRepository,
        scans: ScanRepository,
        assessments: AssessmentRepository,
        uow: UnitOfWork,
        clock: Clock,
    ) -> None:
        self.analysis = analysis
        self.scans = scans
        self.assessments = assessments
        self.uow = uow
        self.clock = clock

    def _require_scan(self, scan_id: uuid.UUID) -> None:
        if self.scans.get(scan_id) is None:
            raise NotFoundError("scan not found")

    def get(self, finding_id: uuid.UUID) -> Finding:
        finding = self.analysis.get_finding(finding_id)
        if finding is None:
            raise NotFoundError("finding not found")
        return finding

    def rule_metadata(self, finding: Finding) -> dict[str, Any]:
        stored = self.analysis.get_rule_version(finding.rule_id, finding.rule_version)
        assert stored is not None  # noqa: S101  # guaranteed by the foreign key
        return stored.rule_metadata

    def list_for_scan(
        self, scan_id: uuid.UUID, filters: dict[str, str], *, limit: int, offset: int
    ) -> Sequence[Finding]:
        self._require_scan(scan_id)
        return self.analysis.list_findings(scan_id, filters, limit=limit, offset=offset)

    def summary_for_scan(self, scan_id: uuid.UUID) -> dict[str, Any]:
        self._require_scan(scan_id)
        return self._summary(scan_id=scan_id)

    def summary_for_assessment(self, assessment_id: uuid.UUID) -> dict[str, Any]:
        if self.assessments.get(assessment_id) is None:
            raise NotFoundError("assessment not found")
        return self._summary(assessment_id=assessment_id)

    def _summary(
        self, *, scan_id: uuid.UUID | None = None, assessment_id: uuid.UUID | None = None
    ) -> dict[str, Any]:
        summary: dict[str, Any] = {
            key: self.analysis.count_by(column, scan_id=scan_id, assessment_id=assessment_id)
            for key, column in _SUMMARY_COLUMNS.items()
        }
        summary["total"] = sum(summary["by_status"].values())
        return summary

    def evidence(self, finding_id: uuid.UUID) -> Sequence[Evidence]:
        self.get(finding_id)
        return self.analysis.finding_evidence(finding_id)

    def history(self, finding_id: uuid.UUID) -> Sequence[FindingStatusChange]:
        self.get(finding_id)
        return self.analysis.history(finding_id)

    def analysis_runs(self, scan_id: uuid.UUID) -> Sequence[AnalysisRun]:
        self._require_scan(scan_id)
        return self.analysis.runs_for_scan(scan_id)

    def triage(
        self, finding_id: uuid.UUID, status: FindingStatus, reason: str | None, triaged_by: str
    ) -> Finding:
        """Change a finding's triage status and append the change to its
        history, under the finding's row lock (concurrent triage serializes)."""
        finding = self.analysis.get_finding_for_update(finding_id)
        if finding is None:
            raise NotFoundError("finding not found")
        if finding.status == status:
            raise InvalidStateTransitionError(
                f"the finding is already {status.value}", field="status"
            )
        now = self.clock()
        self.analysis.add_status_change(
            FindingStatusChange(
                finding_id=finding.id,
                from_status=FindingStatus(finding.status).value,
                to_status=status.value,
                reason=reason,
                changed_by=triaged_by,
                changed_at=now,
            )
        )
        finding.status = status
        finding.status_reason = reason
        finding.status_changed_at = now
        finding.status_changed_by = triaged_by
        self.analysis.flush()
        self.uow.commit()
        return finding
