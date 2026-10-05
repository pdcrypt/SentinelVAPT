"""Account administration (ADR 0014, Phase 9 M7): global administrators
create accounts, list them, disable them and reset their passwords.

Built on the M2 primitives: the same username rule, password policy and
Argon2id hashing, the same session revocation. There is no registration and
no deletion (users are disabled; they remain the historical actors of what
they did).

Rules:
- A new account gets the temporary password the administrator chose and must
  change it at first sign-in. Nothing ever returns a password or a hash.
- Disabling revokes every session of the account in the same transaction.
  The platform keeps at least one active administrator (also enforced by a
  deferred database trigger), and administrators cannot disable or reset
  themselves here (they change their own password with /auth/password).
- A password reset replaces the credential, revokes every session and
  requires a change at next sign-in.
- Enabling (M10) makes a disabled account able to sign in again. Nothing else
  changes: the credential and must_change_password stay as they were, and
  every session revoked when it was disabled stays revoked (revocation is
  final in the database), so the user signs in afresh.
- A global-role change (M10) revokes every session of the account (reason
  role_changed), so the new role starts with a fresh sign-in. Administrators
  cannot change their own role: promoting oneself is meaningless and stepping
  down is done by another administrator, so an administrator can never lock
  the platform out by accident. A disabled account cannot be promoted (also
  refused by a database trigger), and demoting the last active administrator
  is refused (M7's deferred trigger is the backstop). Global roles never touch
  project membership.
- Every change, and every refusal of one, is audited in the same transaction
  as the change (refusals are committed before the error is raised).
"""

import re
import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.actors import UserActor, require_user_actor
from app.core.audit import AuditAction
from app.core.clock import Clock
from app.core.errors import ConflictError, DomainValidationError, NotFoundError
from app.core.passwords import PasswordPolicyError, Passwords, check_policy
from app.models import User, UserCredential
from app.models.enums import GlobalRole, SessionRevocationReason
from app.models.identity import USERNAME_PATTERN
from app.repositories.identity import SessionRepository, UserRepository
from app.services.audit import AuditService

_USERNAME = re.compile(USERNAME_PATTERN)
ADMINS_LOCK = "platform:admins"  # the advisory lock of the keep-an-admin rule


def parse_user_id(raw: str) -> uuid.UUID:
    """A malformed id is simply a user that does not exist."""
    try:
        return uuid.UUID(raw)
    except ValueError:
        raise NotFoundError("user not found") from None


class UserAdministrationService:
    def __init__(
        self, session: Session, clock: Clock, passwords: Passwords, audit: AuditService
    ) -> None:
        self.session = session
        self.users = UserRepository(session)
        self.sessions = SessionRepository(session)
        self.clock = clock
        self.passwords = passwords
        self.audit = audit

    # --- reads -------------------------------------------------------------------------------

    def list(
        self, *, active: bool | None, global_role: GlobalRole | None, limit: int, offset: int
    ) -> Sequence[User]:
        stmt = select(User)
        if active is not None:
            stmt = stmt.where(User.is_active == active)
        if global_role is not None:
            stmt = stmt.where(User.global_role == global_role)
        stmt = stmt.order_by(User.username, User.id).limit(limit).offset(offset)
        return self.session.scalars(stmt).all()

    def get(self, user_id: uuid.UUID) -> User:
        user = self.session.get(User, user_id)
        if user is None:
            raise NotFoundError("user not found")
        return user

    # --- changes -------------------------------------------------------------------------------

    def _refuse(
        self,
        actor: UserActor,
        operation: str,
        reason: str,
        target: uuid.UUID | None,
        error: Exception,
    ) -> Exception:
        """Records the refusal (committed) and returns the error to raise."""
        self.audit.denial(
            AuditAction.USER_CHANGE_REFUSED,
            actor,
            resource=("user", target) if target else None,
            metadata={"operation": operation, "reason": reason},
        )
        return error

    def create(
        self,
        username: str,
        display_name: str,
        password: str,
        global_role: GlobalRole,
        *,
        actor: UserActor,
    ) -> User:
        actor = require_user_actor(actor)
        if not _USERNAME.fullmatch(username):
            raise DomainValidationError(
                "Usernames are 3-64 characters: letters, digits, '.', '_' or '-'.",
                field="username",
            )
        display = display_name.strip()
        if not 1 <= len(display) <= 200:
            raise DomainValidationError("Enter a display name.", field="display_name")
        try:
            check_policy(password, username=username)
        except PasswordPolicyError as exc:
            raise DomainValidationError(str(exc), field="password") from None
        # One creation per account name at a time (the same lock as sign-in).
        self.users.lock(f"auth:account:{username.lower()}")
        if self.users.by_username(username) is not None:
            raise self._refuse(
                actor,
                "create",
                "username_taken",
                None,
                ConflictError("that username is already taken", field="username"),
            )
        user = User(
            username=username,
            display_name=display,
            global_role=global_role,
            must_change_password=True,  # the administrator chose this password
        )
        self.session.add(user)
        try:
            self.session.flush()
        except IntegrityError:
            raise self._refuse(
                actor,
                "create",
                "username_taken",
                None,
                ConflictError("that username is already taken", field="username"),
            ) from None
        self.session.add(
            UserCredential(user_id=user.id, password_hash=self.passwords.hash(password))
        )
        self.session.flush()
        self.audit.user(
            AuditAction.USER_CREATED,
            actor,
            resource=("user", user.id),
            metadata={"global_role": global_role.value, "bootstrap": False},
        )
        self.session.commit()
        return user

    def disable(self, user_id: uuid.UUID, *, actor: UserActor) -> User:
        actor = require_user_actor(actor)
        if user_id == actor.user_id:
            raise self._refuse(
                actor,
                "disable",
                "self",
                user_id,
                ConflictError("administrators cannot disable themselves"),
            )
        # Lock order: the admins lock, then the user row (then their sessions).
        self.users.lock(ADMINS_LOCK)
        user = self.users.get_for_update(user_id)
        if user is None:
            raise NotFoundError("user not found")
        if not user.is_active:
            raise self._refuse(
                actor,
                "disable",
                "already_disabled",
                user_id,
                ConflictError("the user is already disabled"),
            )
        if user.global_role is GlobalRole.ADMIN and not self._another_active_admin(user.id):
            raise self._refuse(
                actor,
                "disable",
                "last_admin",
                user_id,
                ConflictError("the platform must keep an active administrator"),
            )
        now = self.clock()
        user.is_active = False
        user.disabled_at = now
        revoked = self.sessions.revoke_all(user.id, SessionRevocationReason.USER_DISABLED, now)
        self.session.flush()
        self.audit.user(
            AuditAction.USER_DISABLED,
            actor,
            resource=("user", user.id),
            metadata={"sessions_revoked": revoked},
        )
        self.session.commit()
        return user

    def reset_password(self, user_id: uuid.UUID, password: str, *, actor: UserActor) -> User:
        actor = require_user_actor(actor)
        if user_id == actor.user_id:
            raise self._refuse(
                actor,
                "reset_password",
                "self",
                user_id,
                ConflictError("change your own password with /auth/password"),
            )
        user = self.users.get_for_update(user_id)
        if user is None:
            raise NotFoundError("user not found")
        if not user.is_active:
            raise self._refuse(
                actor, "reset_password", "disabled", user_id, ConflictError("the user is disabled")
            )
        try:
            check_policy(password, username=user.username)
        except PasswordPolicyError as exc:
            raise DomainValidationError(str(exc), field="password") from None
        credential = self.users.credential(user.id)
        new_hash = self.passwords.hash(password)
        if credential is None:  # pragma: no cover  # every account has one
            self.session.add(UserCredential(user_id=user.id, password_hash=new_hash))
        else:
            credential.password_hash = new_hash
            credential.password_changed_at = self.clock()
        user.must_change_password = True
        revoked = self.sessions.revoke_all(
            user.id, SessionRevocationReason.REVOKED_BY_ADMIN, self.clock()
        )
        self.session.flush()
        self.audit.user(
            AuditAction.USER_PASSWORD_RESET,
            actor,
            resource=("user", user.id),
            metadata={"sessions_revoked": revoked},
        )
        self.session.commit()
        return user

    def enable(self, user_id: uuid.UUID, *, actor: UserActor) -> User:
        actor = require_user_actor(actor)
        if user_id == actor.user_id:  # pragma: no cover  # a disabled account has no session
            raise self._refuse(
                actor, "enable", "self", user_id, ConflictError("the account is already active")
            )
        user = self.users.get_for_update(user_id)
        if user is None:
            raise NotFoundError("user not found")
        if user.is_active:
            raise self._refuse(
                actor,
                "enable",
                "already_active",
                user_id,
                ConflictError("the user is already active"),
            )
        user.is_active = True
        user.disabled_at = None
        self.session.flush()
        self.audit.user(AuditAction.USER_ENABLED, actor, resource=("user", user.id))
        self.session.commit()
        return user

    def change_global_role(self, user_id: uuid.UUID, role: GlobalRole, *, actor: UserActor) -> User:
        actor = require_user_actor(actor)
        if user_id == actor.user_id:
            raise self._refuse(
                actor,
                "change_global_role",
                "self",
                user_id,
                ConflictError("administrators cannot change their own global role"),
            )
        # Lock order as in disable(): the admins lock, then the user row.
        self.users.lock(ADMINS_LOCK)
        user = self.users.get_for_update(user_id)
        if user is None:
            raise NotFoundError("user not found")
        previous = GlobalRole(user.global_role)
        if previous is role:
            return user  # nothing changes, nothing to record
        if role is GlobalRole.ADMIN and not user.is_active:
            raise self._refuse(
                actor,
                "change_global_role",
                "disabled",
                user_id,
                ConflictError("a disabled account cannot become an administrator"),
            )
        if (
            previous is GlobalRole.ADMIN
            and user.is_active
            and not self._another_active_admin(user.id)
        ):
            # Reachable when two administrators demote each other at once: the
            # second, serialized behind the admins lock, finds no other.
            raise self._refuse(
                actor,
                "change_global_role",
                "last_admin",
                user_id,
                ConflictError("the platform must keep an active administrator"),
            )
        user.global_role = role
        revoked = self.sessions.revoke_all(
            user.id, SessionRevocationReason.ROLE_CHANGED, self.clock()
        )
        self.session.flush()
        self.audit.user(
            AuditAction.USER_GLOBAL_ROLE_CHANGED,
            actor,
            resource=("user", user.id),
            metadata={
                "from_role": previous.value,
                "to_role": role.value,
                "sessions_revoked": revoked,
            },
        )
        self.session.commit()
        return user

    def _another_active_admin(self, user_id: uuid.UUID) -> bool:
        stmt = select(User.id).where(
            User.global_role == GlobalRole.ADMIN, User.is_active.is_(True), User.id != user_id
        )
        return self.session.scalar(stmt.limit(1)) is not None
