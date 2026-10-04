import uuid

from sqlalchemy.orm import Session

from app.db.base import Base


class SqlRepository[M: Base]:
    """Common persistence operations. Repositories flush but never commit;
    committing is the service's decision (unit of work)."""

    model: type[M]

    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, obj: M) -> M:
        self.session.add(obj)
        self.session.flush()
        return obj

    def get(self, obj_id: uuid.UUID) -> M | None:
        return self.session.get(self.model, obj_id)

    def delete(self, obj: M) -> None:
        self.session.delete(obj)
        self.session.flush()

    def flush(self) -> None:
        self.session.flush()
