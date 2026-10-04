import itertools

import pytest

from app.core.errors import InvalidStateTransitionError
from app.models.enums import AssessmentStatus as S
from app.services.assessments import ALLOWED_TRANSITIONS, ensure_transition

ALLOWED = {
    (S.PLANNED, S.IN_PROGRESS),
    (S.PLANNED, S.CANCELLED),
    (S.IN_PROGRESS, S.COMPLETED),
    (S.IN_PROGRESS, S.CANCELLED),
}


@pytest.mark.parametrize(("current", "new"), list(itertools.product(S, S)))
def test_transition_table(current: S, new: S) -> None:
    if (current, new) in ALLOWED:
        ensure_transition(current, new)
    else:
        with pytest.raises(InvalidStateTransitionError):
            ensure_transition(current, new)


def test_every_status_has_an_entry() -> None:
    assert set(ALLOWED_TRANSITIONS) == set(S)
