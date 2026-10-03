"""Writes and reads for scan results.

Writes use INSERT ... ON CONFLICT on each table's natural key, so persisting the
same scan's results twice changes nothing (ADR 0008). Assets and endpoints use
a no-op DO UPDATE so their existing ids are returned for child rows.
"""

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from app.models import Asset, Endpoint, EndpointCookie, Evidence, ScanLog
from app.repositories.base import SqlRepository


class ScanResultRepository(SqlRepository[Endpoint]):
    model = Endpoint

    # --- writes ------------------------------------------------------------------

    def upsert_asset(self, values: dict[str, Any]) -> uuid.UUID:
        insert_stmt = insert(Asset).values(id=uuid.uuid4(), **values)
        stmt = insert_stmt.on_conflict_do_update(
            constraint="uq_assets_scan_id_scheme_host_port",
            set_={"ip_addresses": insert_stmt.excluded.ip_addresses},
        ).returning(Asset.id)
        asset_id: uuid.UUID = self.session.execute(stmt).scalar_one()
        return asset_id

    def upsert_endpoint(self, values: dict[str, Any]) -> uuid.UUID:
        insert_stmt = insert(Endpoint).values(id=uuid.uuid4(), **values)
        stmt = insert_stmt.on_conflict_do_update(
            constraint="uq_endpoints_scan_id_fingerprint",
            set_={"fingerprint": insert_stmt.excluded.fingerprint},  # no-op; returns the id
        ).returning(Endpoint.id)
        endpoint_id: uuid.UUID = self.session.execute(stmt).scalar_one()
        return endpoint_id

    def insert_cookie(self, values: dict[str, Any]) -> None:
        stmt = insert(EndpointCookie).values(id=uuid.uuid4(), **values)
        self.session.execute(
            stmt.on_conflict_do_nothing(constraint="uq_endpoint_cookies_endpoint_id_name")
        )

    def insert_evidence(self, values: dict[str, Any]) -> None:
        stmt = insert(Evidence).values(id=uuid.uuid4(), **values)
        self.session.execute(
            stmt.on_conflict_do_nothing(constraint="uq_evidence_scan_id_scanner_evidence_id")
        )

    def insert_log(self, values: dict[str, Any]) -> None:
        stmt = insert(ScanLog).values(id=uuid.uuid4(), **values)
        self.session.execute(
            stmt.on_conflict_do_nothing(constraint="uq_scan_logs_scan_id_sequence")
        )

    # --- reads -------------------------------------------------------------------

    def list_logs(self, scan_id: uuid.UUID, *, limit: int, offset: int) -> Sequence[ScanLog]:
        stmt = (
            select(ScanLog)
            .where(ScanLog.scan_id == scan_id)
            .order_by(ScanLog.sequence)
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()

    def list_assets(self, scan_id: uuid.UUID, *, limit: int, offset: int) -> Sequence[Asset]:
        stmt = (
            select(Asset)
            .where(Asset.scan_id == scan_id)
            .order_by(Asset.host, Asset.port, Asset.scheme)
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()

    def list_endpoints(
        self,
        scan_id: uuid.UUID,
        *,
        limit: int,
        offset: int,
        fetched: bool | None = None,
        skip_reason: str | None = None,
        source: str | None = None,
        method: str | None = None,
    ) -> Sequence[Endpoint]:
        stmt = select(Endpoint).where(Endpoint.scan_id == scan_id)
        if fetched is not None:
            stmt = stmt.where(Endpoint.fetched.is_(fetched))
        if skip_reason is not None:
            stmt = stmt.where(Endpoint.skip_reason == skip_reason)
        if source is not None:
            stmt = stmt.where(Endpoint.source == source)
        if method is not None:
            stmt = stmt.where(Endpoint.method == method.upper())
        stmt = stmt.order_by(Endpoint.url, Endpoint.method).limit(limit).offset(offset)
        return self.session.scalars(stmt).all()

    def cookies_for(self, endpoint_ids: Sequence[uuid.UUID]) -> Sequence[EndpointCookie]:
        if not endpoint_ids:
            return []
        stmt = (
            select(EndpointCookie)
            .where(EndpointCookie.endpoint_id.in_(endpoint_ids))
            .order_by(EndpointCookie.name)
        )
        return self.session.scalars(stmt).all()

    def list_evidence(self, scan_id: uuid.UUID, *, limit: int, offset: int) -> Sequence[Evidence]:
        stmt = (
            select(Evidence)
            .where(Evidence.scan_id == scan_id)
            .order_by(Evidence.url, Evidence.method, Evidence.id)
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()

    def get_evidence(self, evidence_id: uuid.UUID) -> Evidence | None:
        return self.session.get(Evidence, evidence_id)
