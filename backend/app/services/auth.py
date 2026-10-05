"""Platform authentication: login, sessions, logout, password change,
disabling users and the first-admin bootstrap (ADR 0014, Phase 9 M2).

This answers only "who is the authenticated platform user?". It grants no
project access (membership, M3/M4) and never touches target authorization.

- Login always runs Argon2 verification, against the dummy hash for unknown
  users, then decides. Unknown user, wrong password, disabled account and
  throttling all end in the same InvalidCredentialsError, and every failure is
  recorded (and committed) as an audit event, which is the throttling record.
- A session token is 256 bits from `secrets`, generated only after a
  successful login and shown once; only its SHA-256 is stored. A presented
  token is never adopted (no session fixation).
- Validation rejects unknown, revoked, idle-expired and absolutely-expired
  sessions and sessions of disabled users, with one AuthenticationError.
- Password change verifies the current password, enforces the policy, revokes
  every session of the user (including the current one) and issues a fresh
  session.
"""

import hashlib
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.audit import AuditAction
from app.core.clock import Clock
from app.core.config import Settings
from app.core.errors import (
    AuthenticationError,
    ConflictError,
    DomainValidationError,
    InvalidCredentialsError,
    InvalidCurrentPasswordError,
)
from app.core.passwords import PasswordPolicyError, Passwords, check_policy
from app.models import User, UserCredential, UserSession
from app.models.enums import AuditActorType, AuditOutcome, GlobalRole, SessionRevocationReason
from app.models.identity import USERNAME_PATTERN
from app.repositories.identity import AuditRepository, SessionRepository, UserRepository
from app.services.audit import AuditContext, AuditRecorder

TOKEN_BYTES = 32  # 256 bits
MAX_TOKEN_LENGTH = 256
LAST_SEEN_RESOLUTION = timedelta(minutes=1)
_USERNAME = re.compile(USERNAME_PATTERN)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


@dataclass(frozen=True)
class Principal:
    """The authenticated platform user behind a request. Grants no project
    access by itself."""

    user_id: uuid.UUID
    username: str
    display_name: str
    global_role: GlobalRole
    must_change_password: bool
    session_id: uuid.UUID
    session_created_at: datetime
    idle_expires_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class IssuedSession:
    """A new session. `token` is the only copy of the raw token."""

    token: str
    principal: Principal


class AuthService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        clock: Clock,
        passwords: Passwords,
    ) -> None:
        self.session = session
        self.settings = settings
        self.clock = clock
        self.passwords = passwords
        self.users = UserRepository(session)
        self.sessions = SessionRepository(session)
        self.events = AuditRepository(session)
        self.audit = AuditRecorder(self.events)

    # --- login ---------------------------------------------------------------------------

    def login(self, username: str, password: str, context: AuditContext) -> IssuedSession:
        # One login (or password change) at a time per account name, known or
        # not, so throttling counts cannot be raced past.
        self.users.lock(f"auth:account:{username.lower()}")
        user = self.users.by_username(username) if _USERNAME.fullmatch(username) else None
        credential = self.users.credential(user.id) if user is not None else None
        # Always do the Argon2 work, whatever the account state.
        stored = credential.password_hash if credential is not None else self.passwords.dummy_hash
        password_ok = self.passwords.verify(stored, password)

        reason: str | None = None
        if user is None or credential is None:
            reason = "unknown_user"
        elif not user.is_active:
            reason = "disabled"
        elif self._account_throttled(user.id) or self._source_throttled(context.source):
            reason = "throttled"
        elif not password_ok:
            reason = "bad_password"
        if user is None and reason == "unknown_user" and self._source_throttled(context.source):
            reason = "throttled"

        if reason is not None:
            self.audit.record(
                "auth.login_failed",
                AuditOutcome.FAILURE,
                context=context,
                actor_type=AuditActorType.ANONYMOUS,
                resource_type="user" if user is not None else None,
                resource_id=user.id if user is not None else None,
                metadata={"reason": reason},
            )
            self.session.commit()  # the failure must persist: it is the throttle record
            raise InvalidCredentialsError()

        assert user is not None and credential is not None  # noqa: S101  # narrowed above
        if self.passwords.needs_rehash(credential.password_hash):
            credential.password_hash = self.passwords.hash(password)
        now = self.clock()
        user.last_login_at = now
        issued = self._issue(user, now)
        self.audit.record(
            "auth.login",
            AuditOutcome.SUCCESS,
            context=context,
            actor_type=AuditActorType.USER,
            actor_user_id=user.id,
            actor_label=user.username,
            session_id=issued.principal.session_id,
            resource_type="user",
            resource_id=user.id,
        )
        self.session.commit()
        return issued

    def _account_throttled(self, user_id: uuid.UUID) -> bool:
        s = self.settings
        window = self.events.account_failures(user_id, s.auth_throttle_window_seconds)
        if window.count < s.auth_throttle_account_threshold or window.latest is None:
            return False
        excess = window.count - s.auth_throttle_account_threshold
        delay = min(
            s.auth_throttle_account_base_delay_seconds * 2 ** min(excess, 30),
            s.auth_throttle_account_max_delay_seconds,
        )
        return window.now < window.latest + timedelta(seconds=delay)

    def _source_throttled(self, source: str) -> bool:
        s = self.settings
        failures = self.events.source_failures(source, s.auth_throttle_window_seconds)
        return failures >= s.auth_throttle_source_threshold

    def _issue(self, user: User, now: datetime) -> IssuedSession:
        """A brand-new session with a fresh random token (never a presented one)."""
        token = new_token()
        expires_at = now + timedelta(hours=self.settings.auth_session_absolute_hours)
        idle_expires_at = min(
            now + timedelta(minutes=self.settings.auth_session_idle_minutes), expires_at
        )
        row = self.sessions.add(
            UserSession(
                user_id=user.id,
                token_sha256=hash_token(token),
                created_at=now,
                last_seen_at=now,
                idle_expires_at=idle_expires_at,
                expires_at=expires_at,
            )
        )
        return IssuedSession(token, _principal(user, row))

    # --- session validation ----------------------------------------------------------------

    def authenticate(self, token: str | None, context: AuditContext | None = None) -> Principal:
        if not token or len(token) > MAX_TOKEN_LENGTH:
            raise AuthenticationError()
        found = self.sessions.by_token_hash_for_update(hash_token(token))
        if found is None:
            raise AuthenticationError()
        row, user = found
        now = self.clock()
        # A revoked session, or one of a disabled account, being presented is
        # security history (a token kept after logout, a password change or
        # disablement). Plain expiry is routine and is not recorded.
        rejected = (
            "user_disabled"
            if not user.is_active
            else ("revoked" if row.revoked_at is not None else None)
        )
        if rejected is not None:
            self.audit.record(
                AuditAction.AUTH_SESSION_REJECTED,
                AuditOutcome.DENIED,
                context=context or AuditContext(request_id=None, source="internal"),
                actor_type=AuditActorType.ANONYMOUS,
                resource_type="session",
                resource_id=row.id,
                metadata={"reason": rejected, "user_id": str(user.id)},
            )
            self.session.commit()
            raise AuthenticationError()
        if now >= row.idle_expires_at or now >= row.expires_at:
            raise AuthenticationError()
        if now - row.last_seen_at >= LAST_SEEN_RESOLUTION:
            # Activity only moves forward (the database refuses otherwise).
            row.last_seen_at = now
            row.idle_expires_at = max(
                row.idle_expires_at,
                min(now + timedelta(minutes=self.settings.auth_session_idle_minutes),
                    row.expires_at),
            )  # fmt: skip
            self.session.flush()
        self.session.commit()
        return _principal(user, row)

    # --- logout ----------------------------------------------------------------------------

    def logout(self, principal: Principal, context: AuditContext) -> None:
        # Locked and re-checked: a concurrent logout or password change may
        # have revoked it since the request was authenticated.
        row = self.sessions.get_for_update(principal.session_id)
        if row is None or row.revoked_at is not None:
            raise AuthenticationError()
        row.revoked_at = self.clock()
        row.revoked_reason = SessionRevocationReason.LOGOUT
        self.audit.record(
            "auth.logout",
            AuditOutcome.SUCCESS,
            context=context,
            actor_type=AuditActorType.USER,
            actor_user_id=principal.user_id,
            actor_label=principal.username,
            session_id=principal.session_id,
            resource_type="user",
            resource_id=principal.user_id,
        )
        self.session.commit()

    # --- password change -------------------------------------------------------------------

    def change_password(
        self,
        principal: Principal,
        current_password: str,
        new_password: str,
        context: AuditContext,
    ) -> IssuedSession:
        self.users.lock(f"auth:account:{principal.username.lower()}")
        user = self.users.get_for_update(principal.user_id)
        credential = self.users.credential(principal.user_id) if user is not None else None
        session_row = self.sessions.get_for_update(principal.session_id)
        if (
            user is None
            or not user.is_active
            or credential is None
            or session_row is None
            or session_row.revoked_at is not None
        ):
            raise AuthenticationError()
        current_ok = self.passwords.verify(credential.password_hash, current_password)
        if not current_ok or self._account_throttled(user.id):
            self.audit.record(
                "auth.password_change_failed",
                AuditOutcome.FAILURE,
                context=context,
                actor_type=AuditActorType.USER,
                actor_user_id=user.id,
                actor_label=user.username,
                session_id=principal.session_id,
                resource_type="user",
                resource_id=user.id,
                metadata={"reason": "bad_password" if not current_ok else "throttled"},
            )
            self.session.commit()
            raise InvalidCurrentPasswordError()
        try:
            check_policy(new_password, username=user.username)
        except PasswordPolicyError as exc:
            raise DomainValidationError(str(exc), field="new_password") from None
        if self.passwords.verify(credential.password_hash, new_password):
            raise DomainValidationError(
                "The new password must differ from the current one.", field="new_password"
            )

        now = self.clock()
        credential.password_hash = self.passwords.hash(new_password)
        credential.password_changed_at = now
        user.must_change_password = False
        # Every session of the user ends, including this one; a fresh session
        # replaces it, so no token from before the change keeps working.
        self.sessions.revoke_all(user.id, SessionRevocationReason.PASSWORD_CHANGED, now)
        issued = self._issue(user, now)
        self.audit.record(
            "auth.password_changed",
            AuditOutcome.SUCCESS,
            context=context,
            actor_type=AuditActorType.USER,
            actor_user_id=user.id,
            actor_label=user.username,
            session_id=issued.principal.session_id,
            resource_type="user",
            resource_id=user.id,
        )
        self.session.commit()
        return issued

    # --- account state -----------------------------------------------------------------------

    def disable_user(self, user_id: uuid.UUID, context: AuditContext, *, actor: str) -> int:
        """Disable a user and revoke all their sessions in one transaction;
        returns the number of sessions revoked. (The administration API that
        calls this is M7.)"""
        user = self.users.get_for_update(user_id)
        if user is None:
            raise AuthenticationError()
        now = self.clock()
        if user.is_active:
            user.is_active = False
            user.disabled_at = now
        revoked = self.sessions.revoke_all(user.id, SessionRevocationReason.USER_DISABLED, now)
        self.audit.record(
            "user.disabled",
            AuditOutcome.SUCCESS,
            context=context,
            actor_type=AuditActorType.SYSTEM,
            actor_label=actor[:200],
            resource_type="user",
            resource_id=user.id,
            metadata={"sessions_revoked": revoked},
        )
        self.session.commit()
        return revoked

    def create_first_admin(
        self,
        username: str,
        display_name: str,
        password: str,
        context: AuditContext,
        *,
        actor: str,
    ) -> User:
        """The bootstrap: creates the first administrator, and refuses once any
        administrator exists. Serialized by an advisory lock, so concurrent
        bootstraps cannot both succeed."""
        self.users.lock("auth:bootstrap-admin")
        if self.users.admin_exists():
            raise ConflictError("an administrator already exists; bootstrap refused")
        if not _USERNAME.fullmatch(username):
            raise DomainValidationError(
                "Usernames are 3-64 characters: letters, digits, '.', '_' or '-'.",
                field="username",
            )
        display = display_name.strip()
        if not 1 <= len(display) <= 200 or "\x00" in display:
            raise DomainValidationError("Enter a display name.", field="display_name")
        try:
            check_policy(password, username=username)
        except PasswordPolicyError as exc:
            raise DomainValidationError(str(exc), field="password") from None
        user = self.users.add(
            User(username=username, display_name=display, global_role=GlobalRole.ADMIN)
        )
        self.session.add(
            UserCredential(user_id=user.id, password_hash=self.passwords.hash(password))
        )
        try:
            self.session.flush()
        except IntegrityError:
            self.session.rollback()
            raise ConflictError("that username is already taken", field="username") from None
        self.audit.record(
            "user.created",
            AuditOutcome.SUCCESS,
            context=context,
            actor_type=AuditActorType.SYSTEM,
            actor_label=actor[:200],
            resource_type="user",
            resource_id=user.id,
            metadata={"global_role": GlobalRole.ADMIN.value, "bootstrap": True},
        )
        self.session.commit()
        return user


def _principal(user: User, row: UserSession) -> Principal:
    return Principal(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        global_role=GlobalRole(user.global_role),
        must_change_password=user.must_change_password,
        session_id=row.id,
        session_created_at=row.created_at,
        idle_expires_at=row.idle_expires_at,
        expires_at=row.expires_at,
    )
