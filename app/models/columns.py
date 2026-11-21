import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, func
from sqlalchemy.orm import Mapped, mapped_column


class CreatedAtMixin:
    """Adds a `created_at` timestamp that the database fills in on insert."""

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


def value_enum(enum_class: type[enum.Enum], name: str) -> Enum:
    """Store a Python enum in PostgreSQL by its values (e.g. "admin"), not its member names."""
    return Enum(
        enum_class, name=name, values_callable=lambda members: [member.value for member in members]
    )
