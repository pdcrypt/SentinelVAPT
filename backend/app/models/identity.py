"""Phase 9 identity and authorization schema (ADR 0014). Milestone M1: tables
and database guarantees only; nothing reads or writes them yet.

Three separate concepts (never derived from one another):
- platform identity: `users` (+ `user_credentials`, `sessions`) — who is signed in;
- project membership: `project_members` — what a user may do within a project;
- target authorization: `target_authorizations` (Phase 1, unchanged) — whether
  a target may be tested at all. Membership never implies it.

Tables:
- users: immutable UUID and username (unique case-insensitively), display name,
  global role (admin | user; grants no project access), active/disabled state.
  Never deleted, only disabled, so actor and audit references stay valid.
- user_credentials: one Argon2id-encoded password hash per user (a CHECK only
  accepts "$argon2id$" strings, so plaintext cannot be stored). Kept apart
  from `users` so no user query ever selects it.
- sessions: server-side sessions. Only the SHA-256 of the opaque token is
  stored; identity, timestamps and the absolute expiry are frozen; revocation
  happens once and is final.
- project_members: (project, user, role). A project with members always keeps
  at least one owner (deferred constraint trigger). Legacy projects have no
  members until an administrator deliberately claims them (later milestone).
- audit_events: append-only security log. Metadata is a flat object of
  allowlisted, scalar values; secret-like keys are rejected.
- platform_settings: one typed row recording when authentication became
  enforced, so actor fields written before then can be told apart from
  authenticated ones without rewriting them.
The triggers that enforce the rules above live in the migration.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum_column
from app.models.enums import (
    AuditActorType,
    AuditOutcome,
    GlobalRole,
    ProjectRole,
    SessionRevocationReason,
)

_SHA256 = "~ '^[0-9a-f]{64}$'"
USERNAME_PATTERN = "^[A-Za-z0-9._-]{3,64}$"


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        # Case-insensitive uniqueness: "Alice" and "alice" are the same user.
        Index("uq_users_username_lower", func.lower(text("username")), unique=True),
        CheckConstraint(f"username ~ '{USERNAME_PATTERN}'", name="username_format"),
        CheckConstraint(
            "length(btrim(display_name)) BETWEEN 1 AND 200", name="display_name_present"
        ),
        CheckConstraint("is_active = (disabled_at IS NULL)", name="disabled_iff_inactive"),
    )

    username: Mapped[str] = mapped_column(String(64))
    display_name: Mapped[str] = mapped_column(String(200))
    global_role: Mapped[GlobalRole] = mapped_column(
        str_enum_column(GlobalRole, "global_role"), server_default=GlobalRole.USER.value
    )
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    must_change_password: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UserCredential(TimestampMixin, Base):
    __tablename__ = "user_credentials"
    __table_args__ = (
        CheckConstraint(
            "password_hash LIKE '$argon2id$%' AND length(password_hash) <= 512",
            name="password_hash_argon2id",
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True
    )
    password_hash: Mapped[str] = mapped_column(Text)
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class UserSession(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_user_id_active", "user_id", postgresql_where=text("revoked_at IS NULL")),
        Index("ix_sessions_expires_at", "expires_at"),
        CheckConstraint(f"token_sha256 {_SHA256}", name="token_sha256_hex"),
        CheckConstraint("expires_at > created_at", name="expires_after_creation"),
        CheckConstraint(
            "idle_expires_at > created_at AND idle_expires_at <= expires_at",
            name="idle_expiry_within_lifetime",
        ),
        CheckConstraint("last_seen_at >= created_at", name="last_seen_after_creation"),
        CheckConstraint(
            "(revoked_at IS NULL) = (revoked_reason IS NULL)", name="revoked_iff_reason"
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    # SHA-256 (hex) of the opaque token; the token itself is never stored.
    token_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[SessionRevocationReason | None] = mapped_column(
        str_enum_column(SessionRevocationReason, "session_revoked_reason")
    )
    user_agent: Mapped[str | None] = mapped_column(String(256))
    client_addr: Mapped[str | None] = mapped_column(INET)


class ProjectMember(Base):
    __tablename__ = "project_members"
    __table_args__ = (Index("ix_project_members_user_id", "user_id"),)

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True
    )
    role: Mapped[ProjectRole] = mapped_column(str_enum_column(ProjectRole, "project_role"))
    # Who added this membership (NULL only for a server-side command).
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AuditEvent(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_project_id_occurred_at", "project_id", text("occurred_at DESC")),
        Index(
            "ix_audit_events_actor_user_id_occurred_at", "actor_user_id", text("occurred_at DESC")
        ),
        Index("ix_audit_events_action_occurred_at", "action", text("occurred_at DESC")),
        CheckConstraint(
            "(actor_type = 'user') = (actor_user_id IS NOT NULL)", name="user_actor_has_user"
        ),
        CheckConstraint("action ~ '^[a-z_]{1,32}\\.[a-z_]{1,32}$'", name="action_format"),
        CheckConstraint(
            "(resource_type IS NULL) = (resource_id IS NULL)", name="resource_type_iff_id"
        ),
        CheckConstraint("resource_type ~ '^[a-z_]{1,32}$'", name="resource_type_format"),
    )

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # Correlates the events of one request (X-Request-ID).
    request_id: Mapped[uuid.UUID | None]
    actor_type: Mapped[AuditActorType] = mapped_column(
        str_enum_column(AuditActorType, "audit_actor_type")
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT")
    )
    # Username or worker id at the time of the event (readable after renames).
    actor_label: Mapped[str | None] = mapped_column(String(200))
    # The session row's id (never the token). Not a foreign key: expired
    # sessions are pruned, audit events are kept.
    session_id: Mapped[uuid.UUID | None]
    action: Mapped[str] = mapped_column(String(65))
    outcome: Mapped[AuditOutcome] = mapped_column(str_enum_column(AuditOutcome, "audit_outcome"))
    # Historical identifiers, not foreign keys: an audit trail must outlive
    # the project or resource it describes.
    project_id: Mapped[uuid.UUID | None]
    resource_type: Mapped[str | None] = mapped_column(String(32))
    resource_id: Mapped[uuid.UUID | None]
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, server_default=text("'{}'::jsonb")
    )


class PlatformSettings(Base):
    __tablename__ = "platform_settings"
    __table_args__ = (CheckConstraint("id = 1", name="singleton"),)

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    # When authentication became enforced. NULL until then; set exactly once.
    # Actor fields written before this instant are self-asserted.
    authentication_enforced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
