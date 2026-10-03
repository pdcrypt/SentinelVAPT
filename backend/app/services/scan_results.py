"""Normalizes a scanner DiscoveryResult into scan_logs, assets, endpoints,
endpoint_cookies and evidence.

Deterministic (rows are written in result order) and idempotent: every write
is keyed on the table's natural unique key, so persisting the same result for
the same scan twice leaves the database unchanged. The scanner has already
redacted everything; nothing here re-reads the target or un-redacts data.
"""

import hashlib
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from app.repositories import ScanResultRepository
from sentinel_scanner.models import DiscoveryResult, PageObservation

_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class LogEntry:
    at: datetime
    level: str
    code: str
    message: str
    url: str | None = None
    data: dict[str, Any] | None = None


@dataclass(frozen=True)
class PersistedCounts:
    logs: int
    assets: int
    endpoints: int
    evidence: int


@dataclass
class _EndpointRow:
    values: dict[str, Any]
    cookies: list[dict[str, Any]] = field(default_factory=list)


def endpoint_fingerprint(method: str, url: str) -> str:
    """Stable identity of an endpoint within (and later across) scans."""
    return hashlib.sha256(f"{method.upper()} {url}".encode()).hexdigest()


def _origin(url: str) -> tuple[str, str, int] | None:
    parts = urlsplit(url)
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
        return None
    try:
        port = parts.port or _DEFAULT_PORTS[parts.scheme]
    except ValueError:
        return None
    return parts.scheme, parts.hostname.lower(), port


def persist_logs(
    repo: ScanResultRepository, scan_id: uuid.UUID, entries: Sequence[LogEntry], *, start: int = 1
) -> int:
    for offset, entry in enumerate(entries):
        repo.insert_log(
            {
                "scan_id": scan_id,
                "sequence": start + offset,
                "at": entry.at,
                "level": entry.level,
                "code": entry.code,
                "message": entry.message,
                "url": entry.url,
                "data": entry.data,
            }
        )
    return len(entries)


def persist_discovery_result(
    repo: ScanResultRepository,
    scan_id: uuid.UUID,
    result: DiscoveryResult,
    *,
    before: Sequence[LogEntry] = (),
    after: Sequence[LogEntry] = (),
) -> PersistedCounts:
    # --- logs: worker entries around the scanner's own events, in order -------
    scanner_events = [
        LogEntry(e.at, e.level.value, e.code, e.message, e.url) for e in result.events
    ]
    logs = persist_logs(repo, scan_id, [*before, *scanner_events, *after])

    # --- assets: every origin actually contacted, with the addresses used -----
    peers = {e.id: e.peer for e in result.evidence}
    asset_ips: dict[tuple[str, str, int], set[str]] = {}
    for page in result.pages:
        origin = _origin(page.url)
        if origin is not None:
            asset_ips.setdefault(origin, set()).add(peers.get(page.evidence_id, ""))
    asset_ids: dict[tuple[str, str, int], uuid.UUID] = {}
    for (scheme, host, port), ips in asset_ips.items():
        asset_ids[(scheme, host, port)] = repo.upsert_asset(
            {
                "scan_id": scan_id,
                "scheme": scheme,
                "host": host,
                "port": port,
                "ip_addresses": sorted(ip for ip in ips if ip),
            }
        )

    # --- endpoints: discovered URLs merged with the pages that were fetched ---
    rows: dict[tuple[str, str], _EndpointRow] = {}
    for endpoint in result.endpoints:
        rows[(endpoint.method, endpoint.url)] = _EndpointRow(
            {
                "method": endpoint.method,
                "url": endpoint.url,
                "source": endpoint.source.value,
                "found_on": endpoint.found_on,
                "fetched": endpoint.fetched,
                "skip_reason": endpoint.skip_reason.value if endpoint.skip_reason else None,
                "query_param_names": list(endpoint.query_param_names),
            }
        )
    evidence_endpoint: dict[str, tuple[str, str]] = {}
    for page in result.pages:
        key = (page.method, page.url)
        row = rows.get(key)
        if row is None:  # e.g. the OPTIONS probe, or past the endpoint cap
            row = rows[key] = _EndpointRow(
                {
                    "method": page.method,
                    "url": page.url,
                    "source": "probe" if page.method == "OPTIONS" else "page",
                    "found_on": None,
                    "fetched": True,
                    "skip_reason": None,
                    "query_param_names": [],
                }
            )
        row.values.update(_page_values(page))
        row.values["fetched"] = True
        row.values["skip_reason"] = None
        seen = {c["name"] for c in row.cookies}
        for cookie in page.cookies:
            if cookie.name not in seen:
                seen.add(cookie.name)
                row.cookies.append(
                    {
                        "name": cookie.name,
                        "secure": cookie.secure,
                        "http_only": cookie.http_only,
                        "same_site": cookie.same_site,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "has_expiry": cookie.has_expiry,
                    }
                )
        evidence_endpoint[page.evidence_id] = key

    endpoint_ids: dict[tuple[str, str], uuid.UUID] = {}
    for key, row in rows.items():
        origin = _origin(row.values["url"])
        values = {
            "depth": None,
            "status_code": None,
            "content_type": None,
            "declared_length": None,
            "body_bytes": None,
            "truncated": None,
            "elapsed_ms": None,
            "title": None,
            "redirect_location": None,
            "allowed_methods": None,
            "tech_hints": [],
            **row.values,
            "scan_id": scan_id,
            "asset_id": asset_ids.get(origin) if origin else None,
            "fingerprint": endpoint_fingerprint(key[0], key[1]),
        }
        endpoint_id = repo.upsert_endpoint(values)
        endpoint_ids[key] = endpoint_id
        for cookie_values in row.cookies:
            repo.insert_cookie({"endpoint_id": endpoint_id, **cookie_values})

    # --- evidence: exactly as redacted by the scanner -------------------------
    for evidence in result.evidence:
        key_for_evidence = evidence_endpoint.get(evidence.id)
        repo.insert_evidence(
            {
                "scan_id": scan_id,
                "endpoint_id": endpoint_ids.get(key_for_evidence) if key_for_evidence else None,
                "scanner_evidence_id": uuid.UUID(evidence.id),
                "method": evidence.method,
                "url": evidence.url,
                "request_headers": [list(h) for h in evidence.request_headers],
                "status_code": evidence.status,
                "response_headers": [list(h) for h in evidence.response_headers],
                "body_excerpt": evidence.body_excerpt,
                "body_sha256": evidence.body_sha256,
                "body_bytes_captured": evidence.body_bytes_captured,
                "truncated": evidence.truncated,
                "peer": evidence.peer,
                "redactions": list(evidence.redactions),
            }
        )

    return PersistedCounts(
        logs=logs, assets=len(asset_ids), endpoints=len(endpoint_ids), evidence=len(result.evidence)
    )


def _page_values(page: PageObservation) -> dict[str, Any]:
    return {
        "depth": page.depth,
        "status_code": page.status,
        "content_type": (page.content_type or "")[:255] or None,
        "declared_length": page.declared_length,
        "body_bytes": page.body_bytes,
        "truncated": page.truncated,
        "elapsed_ms": page.elapsed_ms,
        "title": page.title,
        "redirect_location": page.redirect_location,
        "allowed_methods": page.allowed_methods,
        "tech_hints": [{"source": h.source, "value": h.value} for h in page.hints],
    }
