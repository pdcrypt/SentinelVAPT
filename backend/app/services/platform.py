"""Server-side platform commands for the Phase 9 M4 cutover (ADR 0014).

- Claiming a legacy project: projects that predate project membership (or
  were created by a server-side command) have no members, so nobody can see
  them once authorization is enforced. An operator of the host explicitly
  makes one named, active user their first owner. Nothing is claimed
  implicitly, a project that already has members cannot be claimed (that is
  membership management, M7), and historical actor text is untouched.
- Recording the authentication cutover: `platform_settings.
  authentication_enforced_at` is set once (the database refuses any later
  change). Actor text written before it is self-asserted (M5).

Both run only from python -m app.cli, with the host operator's authority (as
create-admin), and record an audit event in the existing audit log.
"""

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from sqlalchemy import exists, func, select, update
from sqlalchemy.orm import Session

from app.core.errors import DomainError, NotFoundError
from app.models import PlatformSettings, Project, ProjectMember, User
from app.models.enums import AuditActorType, AuditOutcome, ProjectRole
from app.repositories.identity import AuditRepository
from app.services.audit import AuditContext, AuditRecorder


class ClaimRefusedError(DomainError):
    status_code = 409
    code = "claim_refused"


class ClaimOutcome(StrEnum):
    CLAIMED = "claimed"
    ALREADY_OWNER = "already_owner"


@dataclass(frozen=True)
class Cutover:
    enforced_at: datetime
    newly_recorded: bool


class PlatformService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.audit = AuditRecorder(AuditRepository(session))

    def unclaimed_projects(self) -> Sequence[Project]:
        """Projects without any member: visible to nobody until claimed."""
        has_members = exists().where(ProjectMember.project_id == Project.id)
        stmt = select(Project).where(~has_members).order_by(Project.created_at, Project.id)
        return self.session.scalars(stmt).all()

    def claim_project(
        self, project_id: uuid.UUID, username: str, context: AuditContext, *, actor: str
    ) -> ClaimOutcome:
        """Makes `username` the first owner of a project that has no members.
        Idempotent: claiming again for the same owner changes nothing."""
        # The same per-project lock the last-owner trigger takes, so a claim
        # serializes with any concurrent membership change of this project.
        key = f"project_members:{project_id}"
        self.session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(key, 0))))
        project = self.session.get(Project, project_id)
        if project is None:
            raise NotFoundError("project not found")
        user = self.session.scalar(select(User).where(User.username == username))
        if user is None or not user.is_active:
            raise ClaimRefusedError("no active user with that username")
        members = self.session.scalars(
            select(ProjectMember).where(ProjectMember.project_id == project_id)
        ).all()
        if members:
            if any(m.user_id == user.id and m.role is ProjectRole.OWNER for m in members):
                self.session.rollback()
                return ClaimOutcome.ALREADY_OWNER
            raise ClaimRefusedError(
                "the project already has members; only projects without members can be claimed"
            )
        self.session.add(
            ProjectMember(
                project_id=project_id,
                user_id=user.id,
                role=ProjectRole.OWNER,
                created_by_user_id=None,  # a server-side command
            )
        )
        self.audit.record(
            "project.claim",
            AuditOutcome.SUCCESS,
            context=context,
            actor_type=AuditActorType.SYSTEM,
            actor_label=actor,
            project_id=project_id,
            resource_type="project",
            resource_id=project_id,
            metadata={"owner_user_id": str(user.id)},
        )
        self.session.commit()
        return ClaimOutcome.CLAIMED

    def record_authentication_cutover(self, context: AuditContext, *, actor: str) -> Cutover:
        """Sets authentication_enforced_at to the database time, once."""
        recorded = self.session.scalar(
            update(PlatformSettings)
            .where(PlatformSettings.id == 1, PlatformSettings.authentication_enforced_at.is_(None))
            .values(authentication_enforced_at=func.now())
            .returning(PlatformSettings.authentication_enforced_at)
        )
        if recorded is None:
            self.session.rollback()
            existing = self.session.scalar(
                select(PlatformSettings.authentication_enforced_at).where(PlatformSettings.id == 1)
            )
            if existing is None:  # pragma: no cover  # the M1 migration inserts the row
                raise NotFoundError("platform settings are missing")
            return Cutover(existing, newly_recorded=False)
        self.audit.record(
            "platform.auth_enforced",
            AuditOutcome.SUCCESS,
            context=context,
            actor_type=AuditActorType.SYSTEM,
            actor_label=actor,
        )
        self.session.commit()
        return Cutover(recorded, newly_recorded=True)
