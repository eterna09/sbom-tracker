from sqlalchemy import Column, ForeignKey, String, Table, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

version_components = Table(
    "version_components",
    Base.metadata,
    Column(
        "product_version_id",
        ForeignKey("product_versions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "component_id",
        ForeignKey("components.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Component(Base):
    __tablename__ = "components"
    __table_args__ = (UniqueConstraint("ecosystem", "name", "version"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(50))
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(100))