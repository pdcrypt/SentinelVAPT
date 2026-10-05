import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDPrimaryKeyMixin, str_enum_column
from app.models.enums import TargetEnvironment


class TargetAuthorization(UUIDPrimaryKeyMixin, Base):
    """One acknowledged authorization for a target, with the exact scope it covers.

    Append-only: every (re-)authorization or scope change inserts a new record
    with the next `version`; existing records are never modified. A database
    trigger rejects UPDATEs, and DELETEs other than those cascading from the
    deletion of the whole target (only possible while it has no assessments).
    The target points at its current record; assessments point at the record
    they were created under.

    Scope and authorization are validated in app/services/scope.py; the CHECK
    constraints here are a backstop against writes that bypass the service.
    """

    __tablename__ = "target_authorizations"
    __table_args__ = (
        # Leading target_id also serves as the index for per-target lookups.
        UniqueConstraint("target_id", "version"),
        # Redundant with the primary key, but required as the referenced key of
        # the composite foreign keys that tie a record to its own target.
        UniqueConstraint("id", "target_id"),
        CheckConstraint("version >= 1", name="version_positive"),
        CheckConstraint("cardinality(in_scope_hosts) > 0", name="has_in_scope_hosts"),
        CheckConstraint("cardinality(allowed_ports) > 0", name="has_allowed_ports"),
        CheckConstraint(
            "cardinality(in_scope_path_prefixes) > 0", name="has_in_scope_path_prefixes"
        ),
        CheckConstraint("valid_until > valid_from", name="validity_window"),
    )

    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)

    # --- Acknowledged scope (allowlist) ----------------------------------------
    base_url: Mapped[str] = mapped_column(String(2048))
    environment: Mapped[TargetEnvironment] = mapped_column(
        str_enum_column(TargetEnvironment, "target_environment")
    )
    in_scope_hosts: Mapped[list[str]] = mapped_column(ARRAY(String(255)))
    allowed_ports: Mapped[list[int]] = mapped_column(ARRAY(Integer))
    in_scope_path_prefixes: Mapped[list[str]] = mapped_column(ARRAY(String(2048)))
    excluded_paths: Mapped[list[str]] = mapped_column(ARRAY(String(2048)), server_default="{}")

    # --- Authorization -----------------------------------------------------------
    authorized_by: Mapped[str] = mapped_column(String(200))
    reference: Mapped[str] = mapped_column(String(200))
    notes: Mapped[str | None] = mapped_column(Text)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str] = mapped_column(String(200))
    acknowledged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Who acknowledged it (M5, server-set; NULL for records made before M5,
    # whose acknowledged_by text is self-asserted). Users are never deleted.
    acknowledged_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT")
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __mapper_args__ = {"eager_defaults": True}  # noqa: RUF012
