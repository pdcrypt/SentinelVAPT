import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, ForeignKeyConstraint, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.target_authorization import TargetAuthorization

if TYPE_CHECKING:
    from app.models.assessment import Assessment
    from app.models.project import Project


class Target(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A system that may be assessed.

    Its scope and authorization live in append-only TargetAuthorization
    records; `current_authorization_id` points at the one in force.
    """

    __tablename__ = "targets"
    __table_args__ = (
        # Leading project_id also serves as the index for per-project lookups.
        UniqueConstraint("project_id", "name"),
        # The current authorization must belong to this target. Deferred because
        # target and first authorization reference each other: both are inserted
        # in one transaction and checked at commit.
        ForeignKeyConstraint(
            ["current_authorization_id", "id"],
            ["target_authorizations.id", "target_authorizations.target_id"],
            name="fk_targets_current_authorization",
            deferrable=True,
            initially="DEFERRED",
            use_alter=True,
        ),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(200))
    current_authorization_id: Mapped[uuid.UUID]
    created_by: Mapped[str | None] = mapped_column(String(200))

    project: Mapped["Project"] = relationship(back_populates="targets")
    # viewonly: the id is set explicitly by the service, so the ORM never has to
    # resolve the target <-> authorization insert cycle itself.
    current_authorization: Mapped[TargetAuthorization] = relationship(
        primaryjoin=lambda: Target.current_authorization_id == TargetAuthorization.id,
        foreign_keys=lambda: [Target.current_authorization_id],
        viewonly=True,
        lazy="joined",
        innerjoin=True,
    )
    assessments: Mapped[list["Assessment"]] = relationship(
        back_populates="target", passive_deletes="all"
    )
