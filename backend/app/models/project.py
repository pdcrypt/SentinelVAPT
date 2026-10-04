from typing import TYPE_CHECKING

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.target import Target


class Project(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "projects"

    # Not unique since Phase 9 (ADR 0014): names are labels, not identifiers,
    # and global uniqueness would reveal other users' projects. Indexed for
    # lookups by name.
    name: Mapped[str] = mapped_column(String(200), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    # Populated once platform authentication exists (ADR 0005).
    created_by: Mapped[str | None] = mapped_column(String(200))

    # passive_deletes="all": never cascade or null out children from the ORM;
    # the database FK (ON DELETE RESTRICT) is the source of truth.
    targets: Mapped[list["Target"]] = relationship(back_populates="project", passive_deletes="all")
