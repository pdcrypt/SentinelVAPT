"""Report requests and reads (ADR 0010).

A report is requested for one completed, analysed scan of an assessment. The
request builds the immutable snapshot in the same transaction that queues the
report, from persisted, redacted data only; the worker renders it later
without database access. Reports are never edited or deleted.
"""

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy.orm import Session

from app.core.actors import UserActor, require_user_actor
from app.core.audit import AuditAction
from app.core.authz import ResourceType
from app.core.clock import Clock
from app.core.errors import (
    DomainValidationError,
    InvalidStateTransitionError,
    NotFoundError,
    ReportNotAllowedError,
)
from app.models import (
    Assessment,
    Project,
    Report,
    ReportArtifact,
    Scan,
    Target,
    TargetAuthorization,
)
from app.models.enums import AssessmentStatus, ReportKind, ReportStatus, ScanStatus
from app.repositories import AssessmentRepository, ReportRepository, ScanRepository
from app.schemas.report import ReportCreate
from app.services.audit import AuditService
from app.services.base import UnitOfWork
from app.services.report_snapshot import (
    ReportRequest,
    SnapshotSources,
    build_snapshot,
    methodology_rule_keys,
)
from sentinel_reports import (
    SCHEMA_VERSION,
    TEMPLATES,
    ReportError,
    content_digest,
    get_template,
    snapshot_digest,
    validate_snapshot,
)
from sentinel_reports.templates import verified_hash


def display_number(number: int) -> str:
    return f"SV-R-{number:06d}"


class ReportService:
    def __init__(
        self,
        reports: ReportRepository,
        scans: ScanRepository,
        assessments: AssessmentRepository,
        session: Session,
        uow: UnitOfWork,
        clock: Clock,
        *,
        audit: AuditService | None = None,
    ) -> None:
        self.reports = reports
        self.scans = scans
        self.assessments = assessments
        self.session = session
        self.uow = uow
        self.clock = clock
        self.audit = audit or AuditService(session)

    # --- creation -----------------------------------------------------------------------

    def create(self, assessment_id: uuid.UUID, data: ReportCreate, *, actor: UserActor) -> Report:
        actor = require_user_actor(actor)
        assessment = self.assessments.get(assessment_id)
        if assessment is None:
            raise NotFoundError("assessment not found")
        scan = self.scans.get(data.scan_id)
        if scan is None or scan.assessment_id != assessment.id:
            raise NotFoundError("scan not found in this assessment", field="scan_id")
        if scan.status is not ScanStatus.COMPLETED:
            raise ReportNotAllowedError(
                "scan_not_completed", "reports can only be generated from a completed scan"
            )
        run = self.reports.latest_completed_run(scan.id)
        if run is None:
            raise ReportNotAllowedError(
                "analysis_not_completed", "the scan has no completed analysis run"
            )
        if data.kind is ReportKind.FINAL and assessment.status is not AssessmentStatus.COMPLETED:
            raise ReportNotAllowedError(
                "assessment_not_completed", "a final report requires a completed assessment"
            )
        template_id, _, version = data.template.partition("@")
        try:
            template = get_template(template_id, int(version))
            template_hash = verified_hash(template)
        except ReportError as exc:
            raise DomainValidationError("unknown or unusable template", field="template") from exc

        sources = self._sources(assessment, scan, run)
        report_id = uuid.uuid4()
        number = self.reports.next_number()
        now = self.clock()
        snapshot = build_snapshot(
            ReportRequest(
                report_id=report_id,
                number=display_number(number),
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
            validate_snapshot(snapshot)
        except ReportError as exc:
            # The data exceeds what a report can represent (e.g. a bound in the
            # schema). The detail names a location only.
            raise ReportNotAllowedError("snapshot_invalid", exc.detail or exc.code) from exc

        report = Report(
            id=report_id,
            number=number,
            assessment_id=assessment.id,
            target_id=scan.target_id,
            scan_id=scan.id,
            analysis_run_id=run.id,
            kind=data.kind,
            status=ReportStatus.QUEUED,
            title=data.title,
            prepared_by=actor.label,
            requested_by_user_id=actor.user_id,
            reviewed_by=data.reviewed_by,
            classification=data.classification,
            formats=[f.value for f in data.formats],
            template_id=template.id,
            template_version=template.version,
            template_hash=template_hash,
            schema_version=SCHEMA_VERSION,
            snapshot=snapshot,
            snapshot_sha256=snapshot_digest(snapshot),
            content_sha256=content_digest(snapshot),
            created_at=now,
        )
        self.reports.add(report)
        self.reports.add_links(
            report.id,
            scan.id,
            [(f.id, str(f.status)) for f in sources.findings],
            [uuid.UUID(e["id"]) for e in snapshot["evidence"]],
        )
        self.audit.user(
            AuditAction.REPORT_REQUESTED,
            actor,
            resource=(ResourceType.REPORT, report.id),
            metadata={"kind": data.kind.value, "scan_id": str(scan.id)},
        )
        self.uow.commit()
        return report

    def _sources(self, assessment: Assessment, scan: Scan, run: Any) -> SnapshotSources:
        target = self.session.get(Target, scan.target_id)
        authorization = self.session.get(TargetAuthorization, scan.authorization_id)
        assert target is not None and authorization is not None  # noqa: S101  # foreign keys
        project = self.session.get(Project, target.project_id)
        assert project is not None  # noqa: S101  # foreign key
        findings = self.reports.findings_for_run(scan.id, run.id)
        keys = {(f.rule_id, f.rule_version) for f in findings} | set(methodology_rule_keys())
        links = self.reports.evidence_links(f.id for f in findings)
        evidence_ids = {e for ids in links.values() for e in ids}
        return SnapshotSources(
            project=project,
            target=target,
            assessment=assessment,
            # The scan's own authorization record, not the target's current one.
            authorization=authorization,
            scan=scan,
            run=run,
            findings=findings,
            rule_versions=self.reports.rule_versions(keys),
            evidence_links=links,
            evidence=self.reports.evidence_by_ids(scan.id, evidence_ids),
            status_changes=self.reports.status_changes(f.id for f in findings),
        )

    # --- reads ---------------------------------------------------------------------------

    def get(self, report_id: uuid.UUID) -> Report:
        report = self.reports.get(report_id)
        if report is None:
            raise NotFoundError("report not found")
        return report

    def list_for_assessment(
        self, assessment_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[Report]:
        if self.assessments.get(assessment_id) is None:
            raise NotFoundError("assessment not found")
        return self.reports.list_for_assessment(assessment_id, limit=limit, offset=offset)

    def artifacts(self, report_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, list[dict[str, Any]]]:
        grouped: dict[uuid.UUID, list[dict[str, Any]]] = {i: [] for i in report_ids}
        for row in self.reports.artifact_metadata(report_ids):
            grouped[row.report_id].append(dict(row._mapping))
        return grouped

    def artifact(self, report_id: uuid.UUID, fmt: str) -> tuple[Report, ReportArtifact]:
        report = self.get(report_id)
        if report.status is not ReportStatus.COMPLETED:
            raise InvalidStateTransitionError(
                f"the report is {report.status}; artifacts exist only for completed reports",
                field="status",
            )
        artifact = self.reports.artifact(report.id, fmt)
        if artifact is None:
            raise NotFoundError(f"this report has no {fmt} artifact")
        return report, artifact

    @staticmethod
    def templates() -> list[dict[str, Any]]:
        return [
            {
                "id": t.id,
                "version": t.version,
                "title": t.title,
                "description": t.description,
                "sha256": verified_hash(t),
            }
            for t in sorted(TEMPLATES.values(), key=lambda t: (t.id, t.version))
        ]
