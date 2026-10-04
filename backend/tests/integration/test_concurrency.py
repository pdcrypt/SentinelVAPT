"""Real concurrency: separate connections and real commits.

Unlike the other integration tests these commit for real (locks and unique
index waits only happen between genuinely concurrent transactions), so each
test creates its own uniquely named project and deletes everything afterwards.

To make the dangerous interleaving deterministic, request A uses a unit of work
that pauses just before COMMIT, i.e. while it still holds its row lock or its
uncommitted insert, and request B is started during that pause.
"""

import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.errors import DomainValidationError, InvalidStateTransitionError
from app.models import Assessment, Target
from app.models.enums import AssessmentStatus
from app.repositories import (
    AssessmentRepository,
    ProjectRepository,
    TargetAuthorizationRepository,
    TargetRepository,
)
from app.schemas.assessment import AssessmentCreate
from app.schemas.project import ProjectCreate
from app.schemas.target import TargetCreate, TargetUpdate
from app.services.assessments import AssessmentService
from app.services.base import UnitOfWork
from app.services.projects import ProjectService
from app.services.targets import TargetService
from tests.integration.conftest import NOW, authorization_payload, target_payload

pytestmark = pytest.mark.integration

PAUSE_SECONDS = 0.5
TIMEOUT_SECONDS = 10


class PausingCommit:
    """Signals, then waits, before committing: the request keeps its locks and
    uncommitted rows while the other request runs."""

    def __init__(self, session: Session, reached: threading.Event) -> None:
        self.session = session
        self.reached = reached

    def commit(self) -> None:
        self.reached.set()
        time.sleep(PAUSE_SECONDS)
        self.session.commit()


def _service(session: Session, uow: UnitOfWork | None = None) -> TargetService:
    return TargetService(
        TargetRepository(session),
        TargetAuthorizationRepository(session),
        ProjectRepository(session),
        uow or session,
        lambda: NOW,
    )


@dataclass
class Outcome:
    value: Any = None
    error: BaseException | None = None
    finished_at: float = field(default=0.0)


def _start(fn: Callable[[], Any]) -> tuple[threading.Thread, Outcome]:
    outcome = Outcome()

    def run() -> None:
        try:
            outcome.value = fn()
        except BaseException as exc:  # recorded and asserted on by the test
            outcome.error = exc
        outcome.finished_at = time.monotonic()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, outcome


@pytest.fixture
def factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def project_id(factory: sessionmaker[Session]) -> Iterator[uuid.UUID]:
    with factory() as session:
        project = ProjectService(ProjectRepository(session), session).create(
            ProjectCreate(name=f"concurrency-{uuid.uuid4()}")
        )
    yield project.id
    with factory() as session:
        # Assessments first, directly: completed or in-progress ones are
        # (deliberately) not deletable through the service.
        target_ids = select(Target.id).where(Target.project_id == project.id)
        session.execute(delete(Assessment).where(Assessment.target_id.in_(target_ids)))
        session.commit()
        service = _service(session)
        for target in service.list_for_project(project.id, limit=100, offset=0):
            service.delete(target.id)
        ProjectService(ProjectRepository(session), session).delete(project.id)


def _create_target(
    factory: sessionmaker[Session], project_id: uuid.UUID, **overrides: Any
) -> uuid.UUID:
    with factory() as session:
        payload = TargetCreate.model_validate(target_payload(**overrides))
        return _service(session).create(project_id, payload).id


def _update(
    factory: sessionmaker[Session],
    target_id: uuid.UUID,
    body: dict[str, Any],
    reached: threading.Event | None = None,
) -> None:
    with factory() as session:
        uow = PausingCommit(session, reached) if reached else None
        _service(session, uow).update(target_id, TargetUpdate.model_validate(body))


def test_concurrent_updates_cannot_combine_stale_fields(
    factory: sessionmaker[Session], project_id: uuid.UUID
) -> None:
    """The review's failing interleaving: A drops host x from scope while B,
    working from the old state, points base_url at host x. Each is valid on its
    own; combined they would put base_url out of scope."""
    target_id = _create_target(factory, project_id, base_url="http://x/", in_scope_hosts=["x", "y"])
    a_holds_lock = threading.Event()

    thread_a, a = _start(
        lambda: _update(
            factory,
            target_id,
            {
                "base_url": "http://y/",
                "in_scope_hosts": ["y"],
                "authorization": authorization_payload(),
            },
            reached=a_holds_lock,
        )
    )
    assert a_holds_lock.wait(TIMEOUT_SECONDS)
    thread_b, b = _start(
        lambda: _update(
            factory,
            target_id,
            {"base_url": "http://x/app", "authorization": authorization_payload()},
        )
    )
    thread_a.join(TIMEOUT_SECONDS)
    thread_b.join(TIMEOUT_SECONDS)

    assert a.error is None
    # B waited for A's lock, then validated against A's committed scope.
    assert b.finished_at >= a.finished_at
    assert isinstance(b.error, DomainValidationError)
    assert b.error.field == "base_url"

    with factory() as session:
        service = _service(session)
        current = service.get(target_id).current_authorization
        assert (current.version, current.base_url, current.in_scope_hosts) == (
            2,
            "http://y/",
            ["y"],
        )
        history = service.list_authorizations(target_id, limit=10, offset=0)
        assert [r.version for r in history] == [2, 1]


def test_concurrent_reauthorizations_serialize_into_consecutive_versions(
    factory: sessionmaker[Session], project_id: uuid.UUID
) -> None:
    target_id = _create_target(factory, project_id)
    a_holds_lock = threading.Event()

    thread_a, a = _start(
        lambda: _update(
            factory,
            target_id,
            {"authorization": authorization_payload(reference="A")},
            reached=a_holds_lock,
        )
    )
    assert a_holds_lock.wait(TIMEOUT_SECONDS)
    thread_b, b = _start(
        lambda: _update(factory, target_id, {"authorization": authorization_payload(reference="B")})
    )
    thread_a.join(TIMEOUT_SECONDS)
    thread_b.join(TIMEOUT_SECONDS)

    assert (a.error, b.error) == (None, None)
    with factory() as session:
        service = _service(session)
        history = service.list_authorizations(target_id, limit=10, offset=0)
        assert [(r.version, r.reference) for r in history] == [(3, "B"), (2, "A"), (1, "LAB-001")]
        assert service.get(target_id).current_authorization.version == 3


def test_concurrent_duplicate_creation_is_stopped_by_the_database(
    factory: sessionmaker[Session], project_id: uuid.UUID
) -> None:
    """Both requests pass the service-level name check (A's row is not yet
    committed), so the unique constraint must reject B."""
    a_inserted = threading.Event()

    def create(reached: threading.Event | None) -> uuid.UUID:
        with factory() as session:
            uow = PausingCommit(session, reached) if reached else None
            payload = TargetCreate.model_validate(target_payload(name="duplicate"))
            return _service(session, uow).create(project_id, payload).id

    thread_a, a = _start(lambda: create(a_inserted))
    assert a_inserted.wait(TIMEOUT_SECONDS)
    thread_b, b = _start(lambda: create(None))
    thread_a.join(TIMEOUT_SECONDS)
    thread_b.join(TIMEOUT_SECONDS)

    assert a.error is None
    assert isinstance(b.error, IntegrityError)
    with factory() as session:
        targets = _service(session).list_for_project(project_id, limit=10, offset=0)
        assert [t.name for t in targets] == ["duplicate"]


# --- Assessment lifecycle ------------------------------------------------------------


def _assessments(session: Session, uow: UnitOfWork | None = None) -> AssessmentService:
    return AssessmentService(
        AssessmentRepository(session),
        TargetRepository(session),
        ProjectRepository(session),
        uow or session,
        lambda: NOW,
    )


def _plan(factory: sessionmaker[Session], project_id: uuid.UUID, *, started: bool) -> uuid.UUID:
    target_id = _create_target(factory, project_id)
    with factory() as session:
        service = _assessments(session)
        assessment = service.create(target_id, AssessmentCreate(name="lifecycle"))
        if started:
            service.start(assessment.id)
        return assessment.id


def _transition(
    factory: sessionmaker[Session],
    assessment_id: uuid.UUID,
    action: str,
    reached: threading.Event | None = None,
) -> AssessmentStatus:
    with factory() as session:
        uow = PausingCommit(session, reached) if reached else None
        result: AssessmentStatus = getattr(_assessments(session, uow), action)(assessment_id).status
        return result


@pytest.mark.parametrize(
    ("initial_started", "first", "second", "final_status"),
    [
        # The review's failing case: a start racing a cancel. Whichever holds the
        # lock first wins; the other then sees the committed state.
        (False, "start", "cancel", AssessmentStatus.CANCELLED),  # start, then cancel: valid
        (False, "cancel", "start", AssessmentStatus.CANCELLED),  # cancelled is terminal
        (True, "complete", "cancel", AssessmentStatus.COMPLETED),  # completed is terminal
        (True, "cancel", "complete", AssessmentStatus.CANCELLED),  # cancelled is terminal
    ],
)
def test_concurrent_lifecycle_transitions_serialize(
    factory: sessionmaker[Session],
    project_id: uuid.UUID,
    initial_started: bool,
    first: str,
    second: str,
    final_status: AssessmentStatus,
) -> None:
    assessment_id = _plan(factory, project_id, started=initial_started)
    first_holds_lock = threading.Event()

    thread_1, one = _start(lambda: _transition(factory, assessment_id, first, first_holds_lock))
    assert first_holds_lock.wait(TIMEOUT_SECONDS)
    thread_2, two = _start(lambda: _transition(factory, assessment_id, second))
    thread_1.join(TIMEOUT_SECONDS)
    thread_2.join(TIMEOUT_SECONDS)

    assert one.error is None
    # The second operation waited for the first's lock, then decided on its result.
    assert two.finished_at >= one.finished_at
    if final_status is AssessmentStatus.CANCELLED and first == "start":
        assert two.error is None  # in_progress -> cancelled is a valid transition
    else:
        assert isinstance(two.error, InvalidStateTransitionError)

    with factory() as session:
        stored = _assessments(session).get(assessment_id)
        assert stored.status is final_status
        # Timestamps match the serialized history, never a mix of both requests.
        assert (stored.started_at is not None) == (initial_started or first == "start")
        assert (stored.completed_at is not None) == (final_status is AssessmentStatus.COMPLETED)
