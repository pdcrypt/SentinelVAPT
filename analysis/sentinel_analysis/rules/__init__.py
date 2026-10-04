"""The ruleset. An explicit, ordered registry: nothing is discovered dynamically."""

from sentinel_analysis.rules import cookies, cors_methods, disclosure, headers, transport
from sentinel_analysis.rules.base import Rule

REGISTRY: tuple[Rule, ...] = tuple(
    sorted(
        (
            *transport.RULES,
            *headers.RULES,
            *cookies.RULES,
            *disclosure.RULES,
            *cors_methods.RULES,
        ),
        key=lambda rule: rule.meta.id,
    )
)

__all__ = ["REGISTRY", "Rule"]
