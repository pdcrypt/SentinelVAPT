"""Phase 9 M5 actor model invariants (no database): the actor of a human
operation is a UserActor built from the authenticated Principal, every such
service method requires one, no request schema can carry an actor, and no
code reads identity from request headers."""

import ast
import inspect
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import BaseModel

import app
import app.schemas as schemas_package
from app.core.actors import SystemActor, UserActor, require_user_actor
from app.models.enums import GlobalRole
from app.schemas.common import InputModel
from app.services.assessments import AssessmentService
from app.services.auth import Principal
from app.services.findings import FindingService
from app.services.reports import ReportService
from app.services.retest_reports import RetestReportService
from app.services.retests import RetestService
from app.services.scans import ScanService
from app.services.targets import TargetService

APP_DIR = Path(app.__file__).parent

HUMAN_OPERATIONS = [
    TargetService.create,
    TargetService.update,
    AssessmentService.create,
    RetestService.create,
    ScanService.create,
    FindingService.triage,
    ReportService.create,
    RetestReportService.create,
]

# Text a client may still supply that names a person without making them an
# actor of anything in the platform: the external party granting permission
# for a test (authorized_by) and the reviewer named on a report (reviewed_by).
DESCRIPTIVE_PEOPLE = {"authorized_by", "reviewed_by"}
# The login credential names the account being authenticated, not an actor.
CREDENTIALS = {("LoginRequest", "username")}
# M7 administration names the *subject* of the operation, never who performs
# it: the account being created, and the user being added to a project.
CREDENTIALS |= {("UserCreate", "username"), ("MemberAdd", "username")}
ACTOR_LIKE = re.compile(r"(_by|_by_user_id|actor\w*|user_id|username|owner\w*|creator)$")


def principal(display: str = "Alice A.") -> Principal:
    now = datetime(2026, 10, 5, tzinfo=UTC)
    return Principal(
        uuid.uuid4(), "alice", display, GlobalRole.USER, False, uuid.uuid4(), now, now, now
    )


def test_user_actor_comes_from_the_principal() -> None:
    who = principal()
    actor = UserActor.of(who)
    assert actor == UserActor(user_id=who.user_id, label="Alice A.", session_id=who.session_id)
    assert UserActor.of(principal()).user_id != actor.user_id  # never cached or shared


@pytest.mark.parametrize(
    "candidate",
    [SystemActor.WORKER, SystemActor.COMMAND, "system:worker", uuid.uuid4(), "alice", None, 1],
)
def test_human_operations_accept_only_a_user_actor(candidate: object) -> None:
    with pytest.raises(TypeError):
        require_user_actor(candidate)
    actor = UserActor(uuid.uuid4(), "x")
    assert require_user_actor(actor) is actor


def test_system_actors_are_not_user_ids() -> None:
    for actor in SystemActor:
        with pytest.raises(ValueError):
            uuid.UUID(actor.value)


@pytest.mark.parametrize("operation", HUMAN_OPERATIONS, ids=lambda f: f.__qualname__)
def test_every_human_operation_requires_an_explicit_actor(operation: object) -> None:
    parameter = inspect.signature(operation).parameters["actor"]  # type: ignore[arg-type]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty
    assert parameter.annotation in (UserActor, "UserActor")


def _input_models() -> list[type[BaseModel]]:
    found: dict[str, type[BaseModel]] = {}
    for path in Path(schemas_package.__file__).parent.glob("*.py"):
        module = __import__(f"app.schemas.{path.stem}", fromlist=["*"])
        for value in vars(module).values():
            if isinstance(value, type) and issubclass(value, InputModel):
                found[value.__qualname__] = value
    return list(found.values())


def test_no_request_schema_can_name_an_actor() -> None:
    models = _input_models()
    assert len(models) > 10
    for model in models:
        assert model.model_config.get("extra") == "forbid", model
        for name in model.model_fields:
            if name in DESCRIPTIVE_PEOPLE or (model.__qualname__, name) in CREDENTIALS:
                continue
            assert not ACTOR_LIKE.search(name), f"{model.__qualname__}.{name}"


def test_no_code_reads_identity_from_headers() -> None:
    forbidden = re.compile(r"^x-(user|actor|username|user-id|remote-user|forwarded-user)$", re.I)
    for path in APP_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert not forbidden.match(node.value), (path, node.value)
