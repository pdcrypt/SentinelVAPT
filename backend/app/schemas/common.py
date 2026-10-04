from typing import Annotated, Any, ClassVar, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

NameStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
DescriptionStr = Annotated[str, StringConstraints(max_length=5000)]


def _contains_nul(value: Any) -> bool:
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, dict):
        return any(_contains_nul(k) or _contains_nul(v) for k, v in value.items())
    if isinstance(value, list | tuple):
        return any(_contains_nul(v) for v in value)
    return False


def reject_nul(value: Any) -> Any:
    """PostgreSQL text cannot hold NUL (U+0000), so input containing it is
    refused as a validation error (422) instead of failing in the database.
    Other control characters are valid text and are stored as given."""
    if _contains_nul(value):
        raise PydanticCustomError("nul_character", "Text must not contain NUL (U+0000) characters")
    return value


# A free-text query parameter (e.g. a filter compared with stored text).
TextQuery = Annotated[str, AfterValidator(reject_nul)]


class InputModel(BaseModel):
    """Base for request bodies. Unknown fields are rejected so clients cannot
    set server-controlled values (e.g. acknowledged_at, status), and no field
    may contain a NUL character (see reject_nul)."""

    model_config = ConfigDict(extra="forbid")

    @field_validator("*", mode="before")
    @classmethod
    def _reject_nul(cls, value: Any) -> Any:
        return reject_nul(value)


class PatchModel(InputModel):
    """Base for PATCH bodies: omitted fields are left unchanged.

    Sending an explicit null is only allowed for fields listed in
    `nullable_fields`; for anything else it is rejected rather than being
    silently treated as "unchanged".
    """

    nullable_fields: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="after")
    def _reject_explicit_nulls(self) -> Self:
        bad = sorted(
            name
            for name in self.model_fields_set - self.nullable_fields
            if getattr(self, name) is None
        )
        if bad:
            raise ValueError(f"fields cannot be null: {', '.join(bad)}")
        return self


class ReadModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
