"""The database must reject invalid data even if the service layer is bypassed."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.db.base import Base
from app.models import Assessment, Project, Target, TargetAuthorization, User
from app.models.enums import AssessmentStatus, TargetEnvironment

pytestmark = pytest.mark.integration

NOW = datetime(2026, 10, 4, tzinfo=UTC)


def _authorization(target_id: uuid.UUID, **overrides: object) -> TargetAuthorization:
    values: dict[str, object] = {
        "id": uuid.uuid4(),
        "target_id": target_id,
        "version": 1,
        "base_url": "http://lab/",
        "environment": TargetEnvironment.LOCAL_LAB,
        "in_scope_hosts": ["lab"],
        "allowed_ports": [80],
        "in_scope_path_prefixes": ["/"],
        "authorized_by": "owner",
        "reference": "ref",
        "valid_from": NOW,
        "valid_until": NOW + timedelta(days=1),
        "acknowledged_by": "tester",
        "acknowledged_by_user_id": ACTOR[0],
        "acknowledged_at": NOW,
    }
    values.update(overrides)
    return TargetAuthorization(**values)


def _insert_target(
    db_session: Session, project: Project, name: str = "t"
) -> tuple[Target, TargetAuthorization]:
    target_id = uuid.uuid4()
    authorization = _authorization(target_id)
    target = Target(
        id=target_id, project_id=project.id, name=name, current_authorization_id=authorization.id
    )
    # Explicit order: the target -> authorization FK is deferred, the reverse is not.
    db_session.add(target)
    db_session.flush()
    db_session.add(authorization)
    db_session.flush()
    return target, authorization


def _check_now(db_session: Session) -> None:
    """Run deferred constraint checks immediately, as COMMIT would."""
    db_session.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))


def _assert_rejected(
    db_session: Session, *objs: object, exc: type[Exception] = IntegrityError
) -> None:
    with pytest.raises(exc), db_session.begin_nested():
        for obj in objs:
            db_session.add(obj)
            db_session.flush()
        _check_now(db_session)
    db_session.execute(text("SET CONSTRAINTS ALL DEFERRED"))


# The user the rows below are attributed to (Phase 9 M5 requires one on every
# new authorization record and assessment); set per test by the fixture.
ACTOR: list[uuid.UUID] = []


@pytest.fixture(autouse=True)
def actor(db_session: Session) -> Iterator[uuid.UUID]:
    user = User(username=f"constraints-{uuid.uuid4().hex[:8]}", display_name="Constraints")
    db_session.add(user)
    db_session.flush()
    ACTOR[:] = [user.id]
    yield user.id
    ACTOR.clear()


@pytest.fixture
def project(db_session: Session) -> Project:
    project = Project(name="constraints")
    db_session.add(project)
    db_session.flush()
    return project


def test_valid_target_with_authorization_is_accepted(db_session: Session, project: Project) -> None:
    target, authorization = _insert_target(db_session, project)
    _check_now(db_session)
    assert authorization.excluded_paths == []  # server default
    assert authorization.created_at is not None
    assert target.current_authorization.id == authorization.id


@pytest.mark.parametrize(
    "overrides",
    [
        {"in_scope_hosts": []},
        {"allowed_ports": []},
        {"in_scope_path_prefixes": []},
        {"valid_until": NOW - timedelta(seconds=1)},
        {"version": 0},
    ],
)
def test_authorization_check_constraints(
    db_session: Session, project: Project, overrides: dict[str, object]
) -> None:
    target, _ = _insert_target(db_session, project)
    _assert_rejected(db_session, _authorization(target.id, **{"version": 2, **overrides}))


def test_environment_check_constraint(db_session: Session, project: Project) -> None:
    # The ORM refuses unknown enum values itself, so go around it with raw SQL.
    target, _ = _insert_target(db_session, project)
    with pytest.raises(IntegrityError, match="target_environment"), db_session.begin_nested():
        db_session.execute(
            text(
                "INSERT INTO target_authorizations (id, target_id, version, base_url, "
                "environment, in_scope_hosts, allowed_ports, in_scope_path_prefixes, "
                "authorized_by, reference, valid_from, valid_until, acknowledged_by, "
                "acknowledged_at, acknowledged_by_user_id) VALUES (gen_random_uuid(), :t, 2, "
                "'http://lab/', 'production', '{lab}', '{80}', '{/}', 'o', 'r', now(), "
                "now() + interval '1 day', 'a', now(), :u)"
            ),
            {"t": target.id, "u": ACTOR[0]},
        )


def test_authorization_versions_are_unique_per_target(
    db_session: Session, project: Project
) -> None:
    target, _ = _insert_target(db_session, project)
    _assert_rejected(db_session, _authorization(target.id, version=1))


def test_target_requires_its_current_authorization_to_exist(
    db_session: Session, project: Project
) -> None:
    orphan = Target(project_id=project.id, name="orphan", current_authorization_id=uuid.uuid4())
    _assert_rejected(db_session, orphan)


def test_current_authorization_must_belong_to_the_same_target(
    db_session: Session, project: Project
) -> None:
    _, other_authorization = _insert_target(db_session, project, "other")
    thief = Target(
        project_id=project.id, name="thief", current_authorization_id=other_authorization.id
    )
    _assert_rejected(db_session, thief)


def test_target_requires_existing_project(db_session: Session) -> None:
    ghost = Project(id=uuid.uuid4(), name="ghost")
    target_id = uuid.uuid4()
    authorization = _authorization(target_id)
    _assert_rejected(
        db_session,
        Target(
            id=target_id,
            project_id=ghost.id,
            name="t",
            current_authorization_id=authorization.id,
        ),
    )


def test_assessment_authorization_must_belong_to_its_target(
    db_session: Session, project: Project
) -> None:
    target, _ = _insert_target(db_session, project, "a")
    _, other_authorization = _insert_target(db_session, project, "b")
    _assert_rejected(
        db_session,
        Assessment(
            target_id=target.id,
            authorization_id=other_authorization.id,
            name="x",
            created_by_user_id=ACTOR[0],
        ),
    )


def test_assessment_completed_requires_started(db_session: Session, project: Project) -> None:
    target, authorization = _insert_target(db_session, project)
    _assert_rejected(
        db_session,
        Assessment(
            target_id=target.id,
            authorization_id=authorization.id,
            name="a",
            status=AssessmentStatus.COMPLETED,
            completed_at=NOW,
            created_by_user_id=ACTOR[0],
        ),
    )


# --- Authorization records are immutable ------------------------------------------


def test_authorization_records_cannot_be_updated(db_session: Session, project: Project) -> None:
    _, authorization = _insert_target(db_session, project)
    with pytest.raises(DBAPIError, match="immutable"), db_session.begin_nested():
        db_session.execute(
            text("UPDATE target_authorizations SET reference = 'tampered' WHERE id = :id"),
            {"id": authorization.id},
        )


def test_authorization_records_cannot_be_deleted_while_target_exists(
    db_session: Session, project: Project
) -> None:
    _, authorization = _insert_target(db_session, project)
    with pytest.raises(DBAPIError, match="cannot be deleted"), db_session.begin_nested():
        db_session.execute(
            text("DELETE FROM target_authorizations WHERE id = :id"), {"id": authorization.id}
        )


def test_deleting_an_unassessed_target_removes_its_authorizations(
    db_session: Session, project: Project
) -> None:
    target, authorization = _insert_target(db_session, project)
    db_session.delete(target)
    db_session.flush()
    _check_now(db_session)
    remaining = db_session.scalar(
        text("SELECT count(*) FROM target_authorizations WHERE id = :id"), {"id": authorization.id}
    )
    assert remaining == 0


def test_authorization_used_by_an_assessment_cannot_be_removed(
    db_session: Session, project: Project
) -> None:
    target, authorization = _insert_target(db_session, project)
    db_session.add(
        Assessment(
            target_id=target.id,
            authorization_id=authorization.id,
            name="a",
            created_by_user_id=ACTOR[0],
        )
    )
    db_session.flush()
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.execute(text("DELETE FROM targets WHERE id = :id"), {"id": target.id})


def test_migrations_match_models(engine: Engine) -> None:
    """Fails if a model changes without a matching Alembic migration."""
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []
