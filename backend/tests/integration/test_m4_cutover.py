"""Phase 9 M4 cutover: legacy projects stay invisible until explicitly
claimed (python -m app.cli claim-project), and the authentication cutover is
recorded once (python -m app.cli enforce-authentication)."""

import argparse
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app import cli
from app.api.deps import get_project_service, get_target_service
from app.core.actors import UserActor
from app.core.clock import utc_now
from app.core.config import Settings
from app.models.enums import GlobalRole
from app.schemas.project import ProjectCreate
from app.schemas.target import TargetCreate
from app.services.audit import AuditContext
from app.services.platform import ClaimOutcome, ClaimRefusedError, Cutover, PlatformService
from tests.integration.auth_support import Live, bearer, live, login
from tests.integration.conftest import _test_database_url
from tests.integration.scan_support import authorization, purge_project

pytestmark = pytest.mark.integration

__all__ = ["live"]

API = "/api/v1"
CLI = AuditContext(request_id=None, source="cli")


def cli_settings(live: Live) -> Settings:
    url = _test_database_url().render_as_string(hide_password=False)
    return live.settings.model_copy(update={"database_url": SecretStr(url)})


@pytest.fixture
def legacy(live: Live) -> Iterator[list[uuid.UUID]]:
    """Projects created as before memberships existed (no members), with a
    target carrying self-asserted actor text."""
    created: list[uuid.UUID] = []

    def make(name: str | None = None) -> uuid.UUID:
        with live.factory() as s:
            project = get_project_service(s).create(
                ProjectCreate(name=name or f"legacy-{uuid.uuid4()}"), owner=None
            )
        created.append(project.id)
        return project.id

    make.created = created  # type: ignore[attr-defined]
    yield make  # type: ignore[misc]
    for project_id in created:
        purge_project(live.factory, project_id)


def claim(live: Live, project: uuid.UUID | str, username: str) -> int:
    return cli.claim_project(
        argparse.Namespace(project=str(project), username=username), cli_settings(live)
    )


def members(live: Live, project: uuid.UUID) -> list[Any]:
    return live.rows(
        "SELECT user_id, role, created_by_user_id FROM project_members WHERE project_id = :p",
        p=project,
    )


def claims(live: Live, project: uuid.UUID) -> list[Any]:
    return live.rows(
        "SELECT actor_type, actor_label, action, outcome, resource_type, "
        "resource_id, metadata ->> 'owner_user_id' FROM audit_events "
        "WHERE project_id = :p",
        p=project,
    )


def test_legacy_projects_are_visible_to_nobody(live: Live, legacy: Any) -> None:
    project = legacy()
    client = live.client()
    for role in (GlobalRole.USER, GlobalRole.ADMIN):
        token = login(client, live.user(role=role).username).json()["token"]
        assert client.get(f"{API}/projects", headers=bearer(token)).json() == []
        resp = client.get(f"{API}/projects/{project}", headers=bearer(token))
        assert resp.status_code == 404
        assert resp.json()["detail"] == "project not found"


def test_claim_makes_one_named_user_the_owner_once(
    live: Live, legacy: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    project = legacy()
    other = legacy()
    alice, bob = live.user("alice"), live.user("bob")
    disabled = live.user("disabled", active=False)

    assert cli.list_unclaimed_projects(argparse.Namespace(), cli_settings(live)) == 0
    listed = capsys.readouterr().out
    assert str(project) in listed and str(other) in listed

    assert claim(live, project, alice.username) == 0
    assert "is now the owner" in capsys.readouterr().out
    assert members(live, project) == [(alice.id, "owner", None)]
    assert claims(live, project) == [
        (
            "system",
            "cli:claim-project",
            "project.claim",
            "success",
            "project",
            project,
            str(alice.id),
        )
    ]
    # Idempotent for the same owner; nothing else changes.
    assert claim(live, project, alice.username) == 0
    assert "nothing changed" in capsys.readouterr().out
    assert len(claims(live, project)) == 1
    # Nobody can claim a project that has members.
    assert claim(live, project, bob.username) == 1
    assert "already has members" in capsys.readouterr().err
    assert members(live, project) == [(alice.id, "owner", None)]
    # Unknown or disabled users, unknown projects and malformed ids are refused.
    for target, username in (
        (other, disabled.username),
        (other, "m2-nobody"),
        (uuid.uuid4(), alice.username),
        ("not-a-uuid", alice.username),
    ):
        assert claim(live, target, username) == 1
    assert members(live, other) == []

    client = live.client()
    alice_token = login(client, alice.username).json()["token"]
    bob_token = login(client, bob.username).json()["token"]
    assert [p["id"] for p in client.get(f"{API}/projects", headers=bearer(alice_token)).json()] == [
        str(project)
    ]
    assert client.get(f"{API}/projects/{project}", headers=bearer(alice_token)).status_code == 200
    assert client.get(f"{API}/projects/{project}", headers=bearer(bob_token)).status_code == 404
    # The claimed project keeps its owner (the M1 last-owner invariant).
    with pytest.raises(DBAPIError, match="at least one owner"), live.engine.begin() as conn:
        conn.execute(text("DELETE FROM project_members WHERE project_id = :p"), {"p": project})


def test_concurrent_claims_produce_one_owner(live: Live, legacy: Any) -> None:
    project = legacy()
    users = [live.user(f"racer{i}") for i in range(4)]
    barrier = threading.Barrier(len(users))
    outcomes: list[str] = []

    def run(username: str) -> None:
        with live.factory() as s:
            barrier.wait()
            try:
                outcomes.append(
                    PlatformService(s).claim_project(project, username, CLI, actor="test").value
                )
            except ClaimRefusedError:
                outcomes.append("refused")

    threads = [threading.Thread(target=run, args=(u.username,)) for u in users]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert sorted(outcomes) == ["claimed", "refused", "refused", "refused"]
    rows = members(live, project)
    assert len(rows) == 1 and rows[0][1] == "owner"


def test_claiming_rewrites_no_history(live: Live, legacy: Any) -> None:
    """Actor data recorded before the claim stays exactly as it was."""
    project = legacy("legacy with history")
    acknowledger = live.user("acknowledger")
    with live.factory() as s:
        get_target_service(s, utc_now).create(
            project,
            TargetCreate.model_validate(
                {
                    "name": "Lab",
                    "base_url": "http://lab-target/",
                    "environment": "local_lab",
                    "in_scope_hosts": ["lab-target"],
                    "authorization": authorization(authorized_by="Lab Owner (as stated)"),
                }
            ),
            actor=UserActor(acknowledger.id, acknowledger.display_name),
        )
    user = live.user("historian")
    queries = [
        ("SELECT * FROM projects WHERE id = :p"),
        ("SELECT t.* FROM targets t WHERE t.project_id = :p"),
        (
            "SELECT ta.* FROM target_authorizations ta JOIN targets t ON t.id = ta.target_id "
            "WHERE t.project_id = :p"
        ),
    ]
    before = [live.rows(q, p=project) for q in queries]
    assert claim(live, project, user.username) == 0
    assert [live.rows(q, p=project) for q in queries] == before
    assert before[2] and before[2][0].acknowledged_by == acknowledger.display_name
    assert before[2][0].acknowledged_by_user_id == acknowledger.id


# --- authentication cutover ----------------------------------------------------------------------


def test_cutover_is_recorded_once(db_session: Session) -> None:
    """Runs in the rolled-back test transaction: the shared database keeps
    its NULL cutover for the schema tests."""
    service = PlatformService(db_session)
    first = service.record_authentication_cutover(CLI, actor="cli:enforce-authentication")
    assert first.newly_recorded
    again = PlatformService(db_session).record_authentication_cutover(CLI, actor="x")
    assert (again.enforced_at, again.newly_recorded) == (first.enforced_at, False)
    events = db_session.execute(
        text(
            "SELECT actor_type, actor_label, outcome FROM audit_events "
            "WHERE action = 'platform.auth_enforced'"
        )
    ).all()
    assert events == [("system", "cli:enforce-authentication", "success")]
    with pytest.raises(DBAPIError, match="recorded once"), db_session.begin_nested():
        db_session.execute(text("UPDATE platform_settings SET authentication_enforced_at = NULL"))


def test_enforce_authentication_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    when = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
    results = iter([Cutover(when, newly_recorded=True), Cutover(when, newly_recorded=False)])
    monkeypatch.setattr(
        PlatformService, "record_authentication_cutover", lambda self, context, actor: next(results)
    )
    settings = Settings(database_url=SecretStr("postgresql+psycopg://u:p@127.0.0.1:1/x_test"))
    assert cli.enforce_authentication(argparse.Namespace(), settings) == 0
    assert (
        "Recorded the authentication cutover at 2026-10-05T12:00:00+00:00"
        in capsys.readouterr().out
    )
    assert cli.enforce_authentication(argparse.Namespace(), settings) == 0
    assert "already recorded" in capsys.readouterr().out
    assert ClaimOutcome.CLAIMED.value == "claimed"
