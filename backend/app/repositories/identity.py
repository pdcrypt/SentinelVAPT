"""Persistence for platform identity: users, credentials, sessions and the
audit-backed login-attempt counters (ADR 0014, Phase 9 M2)."""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, text, update

from app.models import AuditEvent, User, UserCredential, UserSession
from app.models.enums import GlobalRole, SessionRevocationReason
from app.repositories.base import SqlRepository

# Audit actions that count as authentication failures / successes for
# throttling. Failures are only ever inserted (audit_events is append-only),
# so concurrent failures cannot corrupt a counter.
FAILURE_ACTIONS = ("auth.login_failed", "auth.password_change_failed")
SUCCESS_ACTIONS = ("auth.login", "auth.password_changed")


@dataclass(frozen=True)
class FailureWindow:
    count: int
    latest: datetime | None
    now: datetime


class UserRepository(SqlRepository[User]):
    model = User

    def by_username(self, username: str) -> User | None:
        stmt = select(User).where(func.lower(User.username) == username.lower())
        return self.session.scalars(stmt).one_or_none()

    def get_for_update(self, user_id: uuid.UUID) -> User | None:
        """The user row, locked FOR NO KEY UPDATE: concurrent changes to the
        user serialize, but foreign-key checks from other transactions (e.g. a
        logout writing its audit event while holding its session row) are not
        blocked, which would otherwise deadlock against session locks."""
        stmt = select(User).where(User.id == user_id).with_for_update(key_share=True)
        return self.session.scalars(stmt.execution_options(populate_existing=True)).one_or_none()

    def admin_exists(self) -> bool:
        stmt = select(User.id).where(User.global_role == GlobalRole.ADMIN).limit(1)
        return self.session.scalar(stmt) is not None

    def credential(self, user_id: uuid.UUID) -> UserCredential | None:
        return self.session.get(UserCredential, user_id)

    def lock(self, key: str) -> None:
        """Transaction-scoped advisory lock (e.g. one login at a time per
        account name)."""
        self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": key}
        )


class SessionRepository(SqlRepository[UserSession]):
    model = UserSession

    def by_token_hash_for_update(self, token_sha256: str) -> tuple[UserSession, User] | None:
        stmt = (
            select(UserSession, User)
            .join(User, User.id == UserSession.user_id)
            .where(UserSession.token_sha256 == token_sha256)
            .with_for_update(of=UserSession)
            .execution_options(populate_existing=True)
        )
        row = self.session.execute(stmt).one_or_none()
        return None if row is None else (row[0], row[1])

    def get_for_update(self, session_id: uuid.UUID) -> UserSession | None:
        """The session row, locked until the transaction ends, so logout,
        password change and validation of one session serialize."""
        stmt = (
            select(UserSession)
            .where(UserSession.id == session_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return self.session.scalars(stmt).one_or_none()

    def revoke_all(
        self,
        user_id: uuid.UUID,
        reason: SessionRevocationReason,
        now: datetime,
    ) -> int:
        """Revoke every active session of the user; returns how many."""
        result = self.session.execute(
            update(UserSession)
            .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason)
            .returning(UserSession.id)
        )
        return len(result.all())


class AuditRepository:
    """Inserts audit events. M2 uses it only for authentication events (and
    as the throttling record); M6 builds the full audit service on it."""

    def __init__(self, session: Any) -> None:
        self.session = session

    def add(self, event: AuditEvent) -> None:
        self.session.add(event)
        self.session.flush()

    def account_failures(self, user_id: uuid.UUID, window_seconds: float) -> FailureWindow:
        """Failures for the account since its last successful login or
        password change, within the window (database time)."""
        row = self.session.execute(
            text(
                """
                SELECT count(*), max(occurred_at), now() FROM audit_events
                WHERE action = ANY(:failures)
                  AND resource_type = 'user' AND resource_id = :user_id
                  AND occurred_at > now() - make_interval(secs => :window)
                  AND occurred_at > COALESCE(
                      (SELECT max(occurred_at) FROM audit_events
                       WHERE action = ANY(:successes) AND actor_user_id = :user_id),
                      '-infinity')
                """
            ),
            {
                "failures": list(FAILURE_ACTIONS),
                "successes": list(SUCCESS_ACTIONS),
                "user_id": user_id,
                "window": window_seconds,
            },
        ).one()
        return FailureWindow(int(row[0]), row[1], row[2])

    def source_failures(self, source: str, window_seconds: float) -> int:
        """Failed logins from one source address within the window."""
        count = self.session.scalar(
            text(
                """
                SELECT count(*) FROM audit_events
                WHERE action = 'auth.login_failed'
                  AND metadata ->> 'source' = :source
                  AND occurred_at > now() - make_interval(secs => :window)
                """
            ),
            {"source": source, "window": window_seconds},
        )
        return int(count or 0)
