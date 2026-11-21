import enum

from sqlalchemy import Enum


def value_enum(enum_class: type[enum.Enum], name: str) -> Enum:
    """Store a Python enum in PostgreSQL by its values (e.g. "admin"), not its member names."""
    return Enum(
        enum_class, name=name, values_callable=lambda members: [member.value for member in members]
    )
