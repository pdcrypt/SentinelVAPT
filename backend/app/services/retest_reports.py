"""Retest report requests and reads (ADR 0012).

A retest report covers exactly one completed comparison of a retest. The
request freezes the snapshot in the same transaction that queues the report
(findings share-locked while their current triage status is read); the report
worker renders it later without database access. An identical repeat request
(same comparison, kind and content) returns the existing report. Retest
reports are never edited or deleted.
"""

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy.orm import Session

from app.core.actors import UserActor, require_user_actor
from app.core.clock import Clock
from app.core.errors import (
    DomainValidationError,
    InvalidStateTransitionError,
    NotFoundError,
    RetestReportNotAllowedError,
)
from app.models import (
    AnalysisRun,
    Assessment,
    Comparison,
    Project,
    RetestReport,
    RetestReportArtifact,
    Scan,
    Target,
    TargetAuthorization,
)
from app.models.enums import AssessmentStatus, ComparisonStatus, ReportKind, ReportStatus
from app.repositories import AssessmentRepository, ReportRepository, RetestReportRepository
from app.schemas.retest_report import RetestReportCreate
from app.services.base import UnitOfWork
from app.services.retest_report_snapshot import (
    LineageEntry,
    RetestReportRequest,
    RetestSources,
    Side,
    build_retest_snapshot,
)
from sentinel_reports import ReportError
from sentinel_reports.retest import (
    RETEST_SCHEMA_VERSION,
    RETEST_TEMPLATES,
    STATES,
    get_retest_template,
    retest_content_digest,
    retest_snapshot_digest,
    validate_retest_snapshot,
    verified_retest_hash,
)

MAX_LINEAGE = 1000


def display_retest_number(number: int) -> str:
    return f"SV-RT-{number:06d}"


class RetestReportService:
    def __init__(
        self,
        reports: RetestReportRepository,
        assessments: AssessmentRepository,
        session: Session,
        uow: UnitOfWork,
        clock: Clock,
    ) -> None:
        self.reports = reports
        self.assessments = assessments
        self.session = session
        self.uow = uow
        self.clock = clock

    # --- creation -----------------------------------------------------------------------

    def create(
        self,
        assessment_id: uuid.UUID,
        comparison_id: uuid.UUID,
        data: RetestReportCreate,
        *,
        actor: UserActor,
    ) -> tuple[RetestReport, bool]:
        """Returns (report, created). An identical existing report keeps its
        original requester."""
        actor = require_user_actor(actor)
        assessment = self.assessments.get(assessment_id)
        if assessment is None:
            raise NotFoundError("assessment not found")
        comparison = self.session.get(Comparison, comparison_id)
        if comparison is None or comparison.current_assessment_id != assessment.id:
            raise NotFoundError("comparison not found for this assessment")
        if comparison.status is not ComparisonStatus.COMPLETED:
            raise RetestReportNotAllowedError(
                "comparison_not_completed", "retest reports require a completed comparison"
            )
        if data.kind is ReportKind.FINAL and assessment.status is not AssessmentStatus.COMPLETED:
            raise RetestReportNotAllowedError(
                "assessment_not_completed", "a final retest report requires a completed retest"
            )
        template_id, _, version = data.template.partition("@")
        try:
            template = get_retest_template(template_id, int(version))
            template_hash = verified_retest_hash(template)
        except ReportError as exc:
            raise DomainValidationError("unknown or unusable template", field="template") from exc

        sources = self._sources(comparison)
        stored_counts = dict((comparison.summary or {}).get("states", {}))
        copied_counts = {s: 0 for s in STATES}
        for record in sources.records:
            copied_counts[str(record.state)] += 1
        if stored_counts != copied_counts:
            raise RetestReportNotAllowedError(
                "snapshot_invalid", "the comparison's records do not match its summary"
            )

        report_id = uuid.uuid4()
        number = self.reports.next_number()
        now = self.clock()
        snapshot = build_retest_snapshot(
            RetestReportRequest(
                report_id=report_id,
                number=display_retest_number(number),
                title=data.title,
                kind=data.kind.value,
                classification=data.classification.value,
                prepared_by=actor.label,
                reviewed_by=data.reviewed_by,
                created_at=now,
                template_id=template.id,
                template_version=template.version,
                executive_summary_note=data.executive_summary_note,
                scope_note=data.scope_note,
            ),
            sources,
        )
        try:
            validate_retest_snapshot(snapshot)
        except ReportError as exc:
            raise RetestReportNotAllowedError("snapshot_invalid", exc.detail or exc.code) from exc

        content = retest_content_digest(snapshot)
        new_id = self.reports.insert_if_new(
            {
                "id": report_id,
                "number": number,
                "comparison_id": comparison.id,
                "target_id": comparison.target_id,
                "baseline_assessment_id": comparison.baseline_assessment_id,
                "baseline_scan_id": comparison.baseline_scan_id,
                "current_assessment_id": comparison.current_assessment_id,
                "current_scan_id": comparison.current_scan_id,
                "kind": data.kind.value,
                "status": ReportStatus.QUEUED.value,
                "title": data.title,
                "prepared_by": actor.label,
                "requested_by_user_id": actor.user_id,
                "reviewed_by": data.reviewed_by,
                "classification": data.classification.value,
                "formats": [f.value for f in data.formats],
                "template_id": template.id,
                "template_version": template.version,
                "template_hash": template_hash,
                "schema_version": RETEST_SCHEMA_VERSION,
                "snapshot": snapshot,
                "snapshot_sha256": retest_snapshot_digest(snapshot),
                "content_sha256": content,
                "created_at": now,
            }
        )
        if new_id is None:
            existing = self.reports.identical(comparison.id, data.kind.value, content)
            assert existing is not None  # noqa: S101  # the conflict means it exists
            self.uow.commit()
            return existing, False
        self.reports.add_evidence_links(
            [
                {
                    "report_id": report_id,
                    "role": e["role"],
                    "evidence_id": uuid.UUID(e["id"]),
                    "baseline_scan_id": comparison.baseline_scan_id
                    if e["role"] == "baseline"
                    else None,
                    "current_scan_id": comparison.current_scan_id
                    if e["role"] == "current"
                    else None,
                }
                for e in snapshot["evidence"]
            ]
        )
        self.uow.commit()
        report = self.reports.get(report_id)
        assert report is not None  # noqa: S101  # just inserted
        return report, True

    def _side(self, assessment_id: uuid.UUID, scan_id: uuid.UUID, run_id: uuid.UUID) -> Side:
        assessment = self.session.get(Assessment, assessment_id)
        scan = self.session.get(Scan, scan_id)
        run = self.session.get(AnalysisRun, run_id)
        assert assessment is not None and scan is not None and run is not None  # noqa: S101
        authorization = self.session.get(TargetAuthorization, assessment.authorization_id)
        assert authorization is not None  # noqa: S101  # foreign key
        return Side(assessment, scan, run, authorization)

    def _sources(self, comparison: Comparison) -> RetestSources:
        repo = self.reports
        records = repo.records(comparison.id)
        finding_ids = [
            i for r in records for i in (r.baseline_finding_id, r.current_finding_id) if i
        ]
        findings = repo.findings_share_locked(finding_ids)
        links = repo.finding_evidence(finding_ids)
        coverage = repo.coverage(comparison.id)
        baseline_ids = {
            e for r in records if r.baseline_finding_id for e in links[r.baseline_finding_id]
        }
        current_ids = {
            e for r in records if r.current_finding_id for e in links[r.current_finding_id]
        } | {e for ids in coverage.values() for e in ids}
        rule_versions = ReportRepository(self.session).rule_versions(
            (f.rule_id, f.rule_version) for f in findings.values()
        )
        target = self.session.get(Target, comparison.target_id)
        assert target is not None  # noqa: S101  # foreign key
        project = self.session.get(Project, target.project_id)
        assert project is not None  # noqa: S101  # foreign key
        return RetestSources(
            project=project,
            target=target,
            comparison=comparison,
            baseline=self._side(
                comparison.baseline_assessment_id,
                comparison.baseline_scan_id,
                comparison.baseline_run_id,
            ),
            retest=self._side(
                comparison.current_assessment_id,
                comparison.current_scan_id,
                comparison.current_run_id,
            ),
            records=records,
            coverage=coverage,
            findings=findings,
            finding_evidence=links,
            evidence={
                "baseline": {
                    e.id: e for e in repo.evidence(comparison.baseline_scan_id, baseline_ids)
                },
                "current": {
                    e.id: e for e in repo.evidence(comparison.current_scan_id, current_ids)
                },
            },
            rule_versions=rule_versions,
            lineage=self._lineage(comparison),
            history=self._history(comparison, records),
        )

    def _lineage(self, comparison: Comparison) -> list[LineageEntry]:
        """The retest chain from the original assessment to this retest. Each
        retest is shown with the comparison that measured the scan its own
        retest was based on (the reported comparison for the last one)."""
        chain: list[Assessment] = []
        current = self.session.get(Assessment, comparison.current_assessment_id)
        while current is not None and len(chain) < MAX_LINEAGE:
            chain.append(current)
            parent_id = current.retest_of_assessment_id
            current = self.session.get(Assessment, parent_id) if parent_id else None
        chain.reverse()
        entries = []
        for position, assessment in enumerate(chain):
            if position == len(chain) - 1:
                used: Comparison | None = comparison
            elif position == 0:
                used = None
            else:
                next_baseline = chain[position + 1].baseline_scan_id
                assert next_baseline is not None  # noqa: S101  # retests have one
                used = self.reports.comparison_for_scan(next_baseline, comparison.policy_version)
                if used is not None and used.status is not ComparisonStatus.COMPLETED:
                    used = None
            summary = self.reports.summary_of(used.id) if used is not None else None
            entries.append(LineageEntry(assessment, used, summary))
        return entries

    def _history(self, comparison: Comparison, records: Sequence[Any]) -> dict[str, dict[str, Any]]:
        """For each record whose reasons refer to the retest chain, the most
        recent earlier comparison record for its identity."""
        wanted = {r.fingerprint for r in records if str(r.state) in ("new", "reopened")}
        history: dict[str, dict[str, Any]] = {}
        previous_id = comparison.previous_comparison_id
        depth = 0
        while previous_id is not None and wanted and depth < MAX_LINEAGE:
            previous = self.session.get(Comparison, previous_id)
            assert previous is not None  # noqa: S101  # foreign key
            states = self.reports.record_states(previous.id)
            owner = self.session.get(Assessment, previous.current_assessment_id)
            assert owner is not None  # noqa: S101  # foreign key
            for fingerprint in sorted(wanted & states.keys()):
                history[fingerprint] = {
                    "comparison_id": str(previous.id),
                    "assessment_id": str(owner.id),
                    "assessment_name": owner.name,
                    "state": states[fingerprint],
                }
            wanted -= states.keys()
            previous_id = previous.previous_comparison_id
            depth += 1
        return history

    # --- reads ---------------------------------------------------------------------------

    def get(self, report_id: uuid.UUID) -> RetestReport:
        report = self.reports.get(report_id)
        if report is None:
            raise NotFoundError("retest report not found")
        return report

    def list_for_assessment(
        self, assessment_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[RetestReport]:
        if self.assessments.get(assessment_id) is None:
            raise NotFoundError("assessment not found")
        return self.reports.list_for_assessment(assessment_id, limit=limit, offset=offset)

    def artifacts(self, report_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, list[dict[str, Any]]]:
        grouped: dict[uuid.UUID, list[dict[str, Any]]] = {i: [] for i in report_ids}
        for row in self.reports.artifact_metadata(report_ids):
            grouped[row.report_id].append(dict(row._mapping))
        return grouped

    def artifact(self, report_id: uuid.UUID, fmt: str) -> tuple[RetestReport, RetestReportArtifact]:
        report = self.get(report_id)
        if report.status is not ReportStatus.COMPLETED:
            raise InvalidStateTransitionError(
                f"the retest report is {report.status}; artifacts exist only once completed",
                field="status",
            )
        artifact = self.reports.artifact(report.id, fmt)
        if artifact is None:
            raise NotFoundError(f"this retest report has no {fmt} artifact")
        return report, artifact

    @staticmethod
    def templates() -> list[dict[str, Any]]:
        return [
            {
                "id": t.id,
                "version": t.version,
                "title": t.title,
                "description": t.description,
                "sha256": verified_retest_hash(t),
            }
            for t in sorted(RETEST_TEMPLATES.values(), key=lambda t: (t.id, t.version))
        ]
