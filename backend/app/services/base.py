from typing import Protocol


class UnitOfWork(Protocol):
    """What a service needs to finish a unit of work. A SQLAlchemy Session
    satisfies this; tests can pass a session bound to a rolled-back transaction."""

    def commit(self) -> None: ...
