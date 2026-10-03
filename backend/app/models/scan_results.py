"""What a scan observed: normalized, scan-scoped, written once at finalize.

Every row belongs to exactly one scan (and is deleted only with it). Unique keys
make re-running persistence for the same scan a no-op (ADR 0008). Composite
foreign keys keep child rows inside their own scan.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDPrimaryKeyMixin


class _CreatedAt:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    __mapper_args__ = {"eager_defaults": True}  # noqa: RUF012


class ScanLog(UUIDPrimaryKeyMixin, _CreatedAt, Base):
    """Scanner events and worker lifecycle entries, in order."""

    __tablename__ = "scan_logs"
    __table_args__ = (UniqueConstraint("scan_id", "sequence"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    sequence: Mapped[int] = mapped_column(Integer)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    level: Mapped[str] = mapped_column(String(16))
    code: Mapped[str] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)  # redacted by the scanner
    data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class Asset(UUIDPrimaryKeyMixin, _CreatedAt, Base):
    """A host:port the scan actually contacted, with the addresses used."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("scan_id", "scheme", "host", "port"),
        UniqueConstraint("id", "scan_id"),  # target of child composite keys
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    scheme: Mapped[str] = mapped_column(String(8))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer)
    ip_addresses: Mapped[list[str]] = mapped_column(ARRAY(String(45)))


class Endpoint(UUIDPrimaryKeyMixin, _CreatedAt, Base):
    """A URL + method discovered by the scan; page fields are set if it was
    requested."""

    __tablename__ = "endpoints"
    __table_args__ = (
        # fingerprint = sha256(method + " " + redacted URL): URLs can be long,
        # so uniqueness is on the fixed-size digest.
        UniqueConstraint("scan_id", "fingerprint"),
        UniqueConstraint("id", "scan_id"),
        ForeignKeyConstraint(
            ["asset_id", "scan_id"],
            ["assets.id", "assets.scan_id"],
            name="fk_endpoints_asset",
            ondelete="CASCADE",
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    asset_id: Mapped[uuid.UUID | None]
    fingerprint: Mapped[str] = mapped_column(String(64))
    method: Mapped[str] = mapped_column(String(16))
    url: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(32))
    found_on: Mapped[str | None] = mapped_column(Text)
    fetched: Mapped[bool] = mapped_column(Boolean)
    skip_reason: Mapped[str | None] = mapped_column(String(32))
    query_param_names: Mapped[list[str]] = mapped_column(ARRAY(String(200)))

    # Observation of the response (null when not requested)
    depth: Mapped[int | None] = mapped_column(Integer)
    status_code: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(255))
    declared_length: Mapped[int | None] = mapped_column(Integer)
    body_bytes: Mapped[int | None] = mapped_column(Integer)
    truncated: Mapped[bool | None] = mapped_column(Boolean)
    elapsed_ms: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str | None] = mapped_column(String(300))
    redirect_location: Mapped[str | None] = mapped_column(Text)
    allowed_methods: Mapped[list[str] | None] = mapped_column(ARRAY(String(16)))
    tech_hints: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)


class EndpointCookie(UUIDPrimaryKeyMixin, _CreatedAt, Base):
    """Cookie name and security attributes. The value is never stored."""

    __tablename__ = "endpoint_cookies"
    __table_args__ = (UniqueConstraint("endpoint_id", "name"),)

    endpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(200))
    secure: Mapped[bool] = mapped_column(Boolean)
    http_only: Mapped[bool] = mapped_column(Boolean)
    same_site: Mapped[str | None] = mapped_column(String(32))
    domain: Mapped[str | None] = mapped_column(String(255))
    path: Mapped[str | None] = mapped_column(Text)
    has_expiry: Mapped[bool] = mapped_column(Boolean)


class Evidence(UUIDPrimaryKeyMixin, _CreatedAt, Base):
    """One redacted HTTP exchange, exactly as the scanner produced it."""

    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("scan_id", "scanner_evidence_id"),
        ForeignKeyConstraint(
            ["endpoint_id", "scan_id"],
            ["endpoints.id", "endpoints.scan_id"],
            name="fk_evidence_endpoint",
            ondelete="CASCADE",
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    endpoint_id: Mapped[uuid.UUID | None]
    scanner_evidence_id: Mapped[uuid.UUID]
    method: Mapped[str] = mapped_column(String(16))
    url: Mapped[str] = mapped_column(Text)
    request_headers: Mapped[list[list[str]]] = mapped_column(JSONB)
    status_code: Mapped[int] = mapped_column(Integer)
    response_headers: Mapped[list[list[str]]] = mapped_column(JSONB)
    body_excerpt: Mapped[str] = mapped_column(Text)
    body_sha256: Mapped[str] = mapped_column(String(64))
    body_bytes_captured: Mapped[int] = mapped_column(Integer)
    truncated: Mapped[bool] = mapped_column(Boolean)
    peer: Mapped[str] = mapped_column(String(45))
    redactions: Mapped[list[str]] = mapped_column(JSONB)
