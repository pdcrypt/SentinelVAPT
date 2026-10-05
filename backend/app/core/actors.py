"""Actor identity (ADR 0014, Phase 9 M5): who receives provenance for an action.

Four questions stay separate:
- authentication: who is making this request (the M2 session -> Principal);
- authorization: may they do it (M3/M4, project membership);
- actor identity: who is recorded as having done it (this module);
- target authorization: may the target be tested at all (Phase 1).

A human action is attributed to a `UserActor`, built only from the
authenticated Principal: its `user_id` is the durable identity (stored in the
`*_user_id` columns, foreign keys to the non-deletable users table) and its
`label` is the display name copied into the existing text columns
(`prepared_by`, `acknowledged_by`, `changed_by`) for documents and history.
No request field, header or username ever selects an actor.

Background work is performed by a `SystemActor`. A system actor is a fixed
value, not a user row: it cannot log in, hold memberships or be named by a
client, and it never stands in for the user who requested the work. Workers
record their own instance id (`claimed_by`) as the performer; the requester
columns are written once, at request time, and the database refuses to
change them.
"""

import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.services.auth import Principal


class SystemActor(StrEnum):
    """Non-human actors. Never stored in a user column."""

    WORKER = "system:worker"  # scan, analysis, comparison and report workers
    COMMAND = "system:command"  # server-side administrative commands (app.cli)


@dataclass(frozen=True)
class UserActor:
    """An authenticated platform user as the actor of a request."""

    user_id: uuid.UUID
    label: str  # display name at the time of the action (descriptive only)
    # The authenticated session the action came through (M6 audit), from the
    # Principal; None outside a request (tests, server code).
    session_id: uuid.UUID | None = None

    @classmethod
    def of(cls, principal: "Principal") -> "UserActor":
        return cls(
            user_id=principal.user_id,
            label=principal.display_name,
            session_id=principal.session_id,
        )


def require_user_actor(actor: object) -> UserActor:
    """Human-only operations accept nothing but a UserActor (fail closed)."""
    if not isinstance(actor, UserActor):
        raise TypeError(f"this operation requires an authenticated user actor, got {actor!r}")
    return actor
