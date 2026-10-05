"""Phase 9 M6 audit vocabulary and metadata policy (no database)."""

import importlib.util
import re
import uuid
from pathlib import Path
from typing import Any

import pytest

import app
from app.core.actors import UserActor
from app.core.audit import (
    DESCRIPTIONS,
    METADATA_KEYS,
    AuditAction,
    AuditMetadataError,
    audit_action,
    validate_metadata,
)
from app.models.enums import AuditActorType, AuditOutcome
from app.services.audit import INTERNAL, AuditRecorder, AuditService

VERSIONS = Path(app.__file__).parent.parent / "alembic" / "versions"
MIGRATIONS = [
    VERSIONS / "20261006_c4f7a2e9d1b6_audit_integrity.py",
    VERSIONS / "20261007_d2b8e6f3a5c7_user_and_membership_administration.py",
    VERSIONS / "20261008_e5c9a7b1d3f2_platform_administration_hardening.py",
]
# The database's own list of keys it refuses (M1 check_audit_event_insert).
SECRET_LIKE = re.compile(
    r"(password|passwd|secret|token|cookie|authorization|credential|private_key|api_key|body|header)"
)


def _actions() -> dict[str, str]:
    """The vocabulary the migrations write, in order."""
    out: dict[str, str] = {}
    for path in MIGRATIONS:
        spec = importlib.util.spec_from_file_location(path.stem, path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        out.update(dict(module.ACTIONS))
    return out


def test_vocabulary_matches_the_database() -> None:
    assert _actions() == {a.value: DESCRIPTIONS[a] for a in AuditAction}
    for action in AuditAction:
        assert re.fullmatch(r"[a-z_]{1,32}\.[a-z_]{1,32}", action.value), action


def test_metadata_allowlist_never_names_a_secret() -> None:
    assert set(METADATA_KEYS) <= set(AuditAction)
    for action, keys in METADATA_KEYS.items():
        for key in keys:
            assert re.fullmatch(r"[a-z][a-z0-9_]{0,39}", key), (action, key)
            assert not SECRET_LIKE.search(key), (action, key)


@pytest.mark.parametrize(
    ("metadata", "problem"),
    [
        ({"password": "x"}, "does not record"),
        ({"reason": "ok", "token": "x"}, "does not record"),
        ({"reason": {"nested": 1}}, "scalar"),
        ({"reason": ["a"]}, "scalar"),
        ({"reason": 1.5}, "scalar"),
        ({"reason": "x" * 257}, "short plain"),
        ({"reason": "a\x00b"}, "short plain"),
        ({"reason": "line\nbreak"}, "short plain"),
        ({"reason": "\x1b[31m"}, "short plain"),
    ],
)
def test_metadata_is_refused_outside_the_policy(metadata: dict[str, Any], problem: str) -> None:
    with pytest.raises(AuditMetadataError, match=problem):
        validate_metadata(AuditAction.SCAN_REQUEST_REFUSED, metadata)


def test_metadata_inside_the_policy_is_kept() -> None:
    assert validate_metadata(
        AuditAction.FINDING_TRIAGED, {"from_status": "open", "to_status": "confirmed"}
    ) == {"from_status": "open", "to_status": "confirmed"}
    assert validate_metadata(AuditAction.AUTH_LOGIN, None) == {}
    with pytest.raises(AuditMetadataError):
        validate_metadata(AuditAction.AUTH_LOGIN, {"reason": "x"})


@pytest.mark.parametrize("action", ["scan.exfiltrated", "AUTH.LOGIN", "", None, 1, "auth.login "])
def test_unknown_actions_are_refused(action: object) -> None:
    with pytest.raises(AuditMetadataError):
        audit_action(action)


class _Events:
    def __init__(self) -> None:
        self.added: list[Any] = []

    def add(self, event: Any) -> None:
        self.added.append(event)


def test_recorder_checks_action_resource_and_metadata() -> None:
    events = _Events()
    recorder = AuditRecorder(events)  # type: ignore[arg-type]
    event_id = recorder.record(
        "auth.login", AuditOutcome.SUCCESS, context=INTERNAL, actor_type=AuditActorType.ANONYMOUS
    )
    assert events.added[0].id == event_id
    assert events.added[0].metadata_ == {"source": "internal"}
    for bad in (
        {"action": "nope"},
        {"resource_type": "users; drop"},
        {"metadata": {"password": "x"}},
    ):
        kwargs: dict[str, Any] = {"action": "auth.login", **bad}
        with pytest.raises(AuditMetadataError):
            recorder.record(
                kwargs.pop("action"),
                AuditOutcome.SUCCESS,
                context=INTERNAL,
                actor_type=AuditActorType.SYSTEM,
                actor_label="t",
                **kwargs,
            )
    assert len(events.added) == 1


def test_system_events_name_a_performer_not_a_user() -> None:
    service = AuditService.__new__(AuditService)  # no session needed: refused before any query
    for performer in ("", UserActor(uuid.uuid4(), "x")):
        with pytest.raises(AuditMetadataError):
            service.system(AuditAction.SCAN_STARTED, performer)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        service.user(AuditAction.SCAN_REQUESTED, "system:worker")  # type: ignore[arg-type]
