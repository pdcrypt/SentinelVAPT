"""Project membership administration (ADR 0014, Phase 9 M7).

Owners manage their project's members (permission membership.manage, checked
by the route's descriptor before anything here runs). Users are named by
username when added and by id afterwards; the project always comes from the
authorized path, never from the body.

Invariants:
- A project with members keeps at least one owner. Every change takes the
  same per-project advisory lock as M1's deferred last-owner trigger (and the
  M4 claim command), then locks the membership row, then checks: so two
  concurrent demotions or removals cannot both remove the last owner, and the
  trigger remains the database's backstop.
- Only active users can be added; a disabled member keeps their row (and
  history) but cannot sign in.
- An owner may remove or demote themselves while another owner remains.
  Operators and viewers cannot manage membership, so they cannot leave a
  project by themselves; an owner removes them.
- There is no administrator shortcut: a global administrator joins a project
  only when one of its owners adds them.

Every change and every refusal is audited (refusals are committed before the
error is raised); a change and its event commit together.
"""

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.actors import UserActor, require_user_actor
from app.core.audit import AuditAction
from app.core.authz import ResourceType
from app.core.errors import ConflictError, NotFoundError
from app.models import ProjectMember, User
from app.models.enums import ProjectRole
from app.services.audit import AuditService


class MembershipService:
    def __init__(self, session: Session, audit: AuditService) -> None:
        self.session = session
        self.audit = audit

    def list(self, project_id: uuid.UUID) -> Sequence[tuple[ProjectMember, User]]:
        stmt = (
            select(ProjectMember, User)
            .join(User, User.id == ProjectMember.user_id)
            .where(ProjectMember.project_id == project_id)
            .order_by(User.username, User.id)
        )
        return [(m, u) for m, u in self.session.execute(stmt).all()]

    # --- changes -------------------------------------------------------------------------------

    def _lock_project(self, project_id: uuid.UUID) -> None:
        self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
            {"k": f"project_members:{project_id}"},
        )

    def _member_for_update(self, project_id: uuid.UUID, user_id: uuid.UUID) -> ProjectMember:
        member = self.session.scalars(
            select(ProjectMember)
            .where(ProjectMember.project_id == project_id, ProjectMember.user_id == user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).one_or_none()
        if member is None:
            raise NotFoundError("project member not found")
        return member

    def _other_owners(self, project_id: uuid.UUID, user_id: uuid.UUID) -> int:
        return int(
            self.session.scalar(
                select(func.count())
                .select_from(ProjectMember)
                .where(
                    ProjectMember.project_id == project_id,
                    ProjectMember.role == ProjectRole.OWNER,
                    ProjectMember.user_id != user_id,
                )
            )
            or 0
        )

    def _refuse(
        self,
        actor: UserActor,
        project_id: uuid.UUID,
        operation: str,
        reason: str,
        user_id: uuid.UUID | None,
        error: Exception,
    ) -> Exception:
        self.audit.denial(
            AuditAction.MEMBERSHIP_CHANGE_REFUSED,
            actor,
            resource=(ResourceType.PROJECT, project_id),
            metadata={
                "operation": operation,
                "reason": reason,
                "user_id": str(user_id) if user_id else None,
            },
        )
        return error

    def add(
        self, project_id: uuid.UUID, username: str, role: ProjectRole, *, actor: UserActor
    ) -> tuple[ProjectMember, User]:
        actor = require_user_actor(actor)
        self._lock_project(project_id)
        user = self.session.scalar(
            select(User).where(func.lower(User.username) == username.lower())
        )
        if user is None:
            raise self._refuse(
                actor,
                project_id,
                "add",
                "unknown_user",
                None,
                NotFoundError("user not found", field="username"),
            )
        if not user.is_active:
            raise self._refuse(
                actor,
                project_id,
                "add",
                "user_disabled",
                user.id,
                ConflictError("the user is disabled", field="username"),
            )
        exists = self.session.get(ProjectMember, (project_id, user.id))
        if exists is not None:
            raise self._refuse(
                actor,
                project_id,
                "add",
                "already_member",
                user.id,
                ConflictError("the user is already a member", field="username"),
            )
        member = ProjectMember(
            project_id=project_id,
            user_id=user.id,
            role=ProjectRole(role),
            created_by_user_id=actor.user_id,
        )
        self.session.add(member)
        self.session.flush()
        self.audit.user(
            AuditAction.MEMBERSHIP_ADDED,
            actor,
            resource=(ResourceType.PROJECT, project_id),
            metadata={"user_id": str(user.id), "role": member.role.value},
        )
        self.session.commit()
        return member, user

    def change_role(
        self, project_id: uuid.UUID, user_id: uuid.UUID, role: ProjectRole, *, actor: UserActor
    ) -> tuple[ProjectMember, User]:
        actor = require_user_actor(actor)
        role = ProjectRole(role)
        self._lock_project(project_id)
        member = self._member_for_update(project_id, user_id)
        previous = ProjectRole(member.role)
        demotes_owner = previous is ProjectRole.OWNER and role is not ProjectRole.OWNER
        if demotes_owner and self._other_owners(project_id, user_id) == 0:
            raise self._refuse(
                actor,
                project_id,
                "change_role",
                "last_owner",
                user_id,
                ConflictError("a project must keep at least one owner"),
            )
        user = self.session.get(User, user_id)
        assert user is not None  # noqa: S101  # foreign key
        if previous is not role:
            member.role = role
            self.session.flush()
            self.audit.user(
                AuditAction.MEMBERSHIP_ROLE_CHANGED,
                actor,
                resource=(ResourceType.PROJECT, project_id),
                metadata={
                    "user_id": str(user_id),
                    "from_role": previous.value,
                    "to_role": role.value,
                },
            )
        self.session.commit()
        return member, user

    def remove(self, project_id: uuid.UUID, user_id: uuid.UUID, *, actor: UserActor) -> None:
        actor = require_user_actor(actor)
        self._lock_project(project_id)
        member = self._member_for_update(project_id, user_id)
        role = ProjectRole(member.role)
        if role is ProjectRole.OWNER and self._other_owners(project_id, user_id) == 0:
            raise self._refuse(
                actor,
                project_id,
                "remove",
                "last_owner",
                user_id,
                ConflictError("a project must keep at least one owner"),
            )
        # Recorded first: the event's project is derived from the project's rows.
        self.audit.user(
            AuditAction.MEMBERSHIP_REMOVED,
            actor,
            resource=(ResourceType.PROJECT, project_id),
            metadata={"user_id": str(user_id), "role": role.value},
        )
        self.session.delete(member)
        self.session.commit()
