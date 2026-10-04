from typing import Annotated, ClassVar, Self

from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator

NameStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
DescriptionStr = Annotated[str, StringConstraints(max_length=5000)]


class InputModel(BaseModel):
    """Base for request bodies. Unknown fields are rejected so clients cannot
    set server-controlled values (e.g. acknowledged_at, status)."""

    model_config = ConfigDict(extra="forbid")


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
