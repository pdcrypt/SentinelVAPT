from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app import __version__
from app.db.session import get_engine


def test_liveness_ok(client: TestClient) -> None:
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": __version__}


def test_readiness_ok_when_db_reachable(app: FastAPI, client: TestClient) -> None:
    app.dependency_overrides[get_engine] = lambda: MagicMock()
    resp = client.get("/api/v1/health/ready")
    assert resp.status_code == 200


def test_readiness_503_when_db_unreachable(app: FastAPI, client: TestClient) -> None:
    engine = MagicMock()
    engine.connect.side_effect = OperationalError("SELECT 1", {}, Exception("down"))
    app.dependency_overrides[get_engine] = lambda: engine

    resp = client.get("/api/v1/health/ready")

    assert resp.status_code == 503
    # Internal error details must not leak to the client.
    assert resp.json() == {"detail": "database unavailable"}
