"""scan execution and results

Revision ID: c75852b880cb
Revises: 581c955e637f
Create Date: 2026-10-04

Written by hand after checking --autogenerate's detection (the enum column is
VARCHAR(32) with one named CHECK, as in the previous revision).
tests/integration/test_db_constraints.py verifies models and migrations agree.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c75852b880cb"
down_revision: str | None = "581c955e637f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _created_at() -> sa.Column[object]:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
    )


def _updated_at() -> sa.Column[object]:
    return sa.Column(
        "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
    )


def _counter(name: str) -> sa.Column[object]:
    return sa.Column(name, sa.Integer(), server_default="0", nullable=False)


def upgrade() -> None:
    # Target of scans' composite foreign key (scan -> its assessment's own
    # target and authorization record).
    op.create_unique_constraint(
        op.f("uq_assessments_id_target_id_authorization_id"),
        "assessments",
        ["id", "target_id", "authorization_id"],
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="queued", nullable=False),
        sa.Column("stop_reason", sa.String(length=32), nullable=True),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_reason", sa.String(length=64), nullable=True),
        sa.Column("claimed_by", sa.String(length=200), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.String(length=1000), nullable=True),
        sa.Column("scanner_version", sa.String(length=32), nullable=True),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("grant_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        _counter("requests_sent"),
        _counter("pages_count"),
        _counter("endpoints_count"),
        _counter("events_count"),
        _counter("evidence_count"),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        _created_at(),
        _updated_at(),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name=op.f("ck_scans_scan_status"),
        ),
        sa.CheckConstraint(
            "status <> 'queued' OR started_at IS NULL", name=op.f("ck_scans_queued_not_started")
        ),
        sa.CheckConstraint(
            "status NOT IN ('running', 'completed') OR started_at IS NOT NULL",
            name=op.f("ck_scans_running_requires_started"),
        ),
        sa.CheckConstraint(
            "status <> 'running' OR claimed_by IS NOT NULL",
            name=op.f("ck_scans_running_requires_worker"),
        ),
        sa.CheckConstraint(
            "(status IN ('completed', 'failed', 'cancelled')) = (finished_at IS NOT NULL)",
            name=op.f("ck_scans_finished_iff_terminal"),
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id", "target_id", "authorization_id"],
            ["assessments.id", "assessments.target_id", "assessments.authorization_id"],
            name="fk_scans_assessment",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scans")),
    )
    op.create_index("ix_scans_assessment_id_created_at", "scans", ["assessment_id", "created_at"])
    op.create_index("ix_scans_status_created_at", "scans", ["status", "created_at"])
    op.create_index(
        "uq_scans_one_active_per_assessment",
        "scans",
        ["assessment_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )

    op.create_table(
        "scan_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        _created_at(),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_scan_logs_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_logs")),
        sa.UniqueConstraint("scan_id", "sequence", name=op.f("uq_scan_logs_scan_id_sequence")),
    )

    op.create_table(
        "assets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("scheme", sa.String(length=8), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("ip_addresses", postgresql.ARRAY(sa.String(length=45)), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name=op.f("fk_assets_scan_id_scans"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
        sa.UniqueConstraint("id", "scan_id", name=op.f("uq_assets_id_scan_id")),
        sa.UniqueConstraint(
            "scan_id", "scheme", "host", "port", name=op.f("uq_assets_scan_id_scheme_host_port")
        ),
    )

    op.create_table(
        "endpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("found_on", sa.Text(), nullable=True),
        sa.Column("fetched", sa.Boolean(), nullable=False),
        sa.Column("skip_reason", sa.String(length=32), nullable=True),
        sa.Column("query_param_names", postgresql.ARRAY(sa.String(length=200)), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("declared_length", sa.Integer(), nullable=True),
        sa.Column("body_bytes", sa.Integer(), nullable=True),
        sa.Column("truncated", sa.Boolean(), nullable=True),
        sa.Column("elapsed_ms", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=True),
        sa.Column("redirect_location", sa.Text(), nullable=True),
        sa.Column("allowed_methods", postgresql.ARRAY(sa.String(length=16)), nullable=True),
        sa.Column("tech_hints", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name=op.f("fk_endpoints_scan_id_scans"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "scan_id"],
            ["assets.id", "assets.scan_id"],
            name="fk_endpoints_asset",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_endpoints")),
        sa.UniqueConstraint("id", "scan_id", name=op.f("uq_endpoints_id_scan_id")),
        sa.UniqueConstraint(
            "scan_id", "fingerprint", name=op.f("uq_endpoints_scan_id_fingerprint")
        ),
    )

    op.create_table(
        "endpoint_cookies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("secure", sa.Boolean(), nullable=False),
        sa.Column("http_only", sa.Boolean(), nullable=False),
        sa.Column("same_site", sa.String(length=32), nullable=True),
        sa.Column("domain", sa.String(length=255), nullable=True),
        sa.Column("path", sa.Text(), nullable=True),
        sa.Column("has_expiry", sa.Boolean(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(
            ["endpoint_id"],
            ["endpoints.id"],
            name=op.f("fk_endpoint_cookies_endpoint_id_endpoints"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_endpoint_cookies")),
        sa.UniqueConstraint(
            "endpoint_id", "name", name=op.f("uq_endpoint_cookies_endpoint_id_name")
        ),
    )

    op.create_table(
        "evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=True),
        sa.Column("scanner_evidence_id", sa.Uuid(), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("request_headers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("response_headers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("body_excerpt", sa.Text(), nullable=False),
        sa.Column("body_sha256", sa.String(length=64), nullable=False),
        sa.Column("body_bytes_captured", sa.Integer(), nullable=False),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("peer", sa.String(length=45), nullable=False),
        sa.Column("redactions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name=op.f("fk_evidence_scan_id_scans"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["endpoint_id", "scan_id"],
            ["endpoints.id", "endpoints.scan_id"],
            name="fk_evidence_endpoint",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence")),
        sa.UniqueConstraint(
            "scan_id", "scanner_evidence_id", name=op.f("uq_evidence_scan_id_scanner_evidence_id")
        ),
    )


def downgrade() -> None:
    op.drop_table("evidence")
    op.drop_table("endpoint_cookies")
    op.drop_table("endpoints")
    op.drop_table("assets")
    op.drop_table("scan_logs")
    op.drop_index("uq_scans_one_active_per_assessment", table_name="scans")
    op.drop_index("ix_scans_status_created_at", table_name="scans")
    op.drop_index("ix_scans_assessment_id_created_at", table_name="scans")
    op.drop_table("scans")
    op.drop_constraint(
        op.f("uq_assessments_id_target_id_authorization_id"), "assessments", type_="unique"
    )
