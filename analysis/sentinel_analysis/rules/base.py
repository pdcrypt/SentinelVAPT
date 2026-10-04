from collections.abc import Callable, Iterable
from dataclasses import dataclass

from sentinel_analysis.context import RuleContext
from sentinel_analysis.model import Match, RuleMeta


@dataclass(frozen=True)
class Rule:
    """Metadata plus a pure evaluation function over a RuleContext."""

    meta: RuleMeta
    evaluate: Callable[[RuleContext], Iterable[Match]]


def wstg_ref(test_id: str) -> str:
    from sentinel_analysis.taxonomy import WSTG_V42

    return WSTG_V42[test_id].source


def cwe_ref(cwe_id: int) -> str:
    from sentinel_analysis.taxonomy import CWE

    return CWE[cwe_id].source
