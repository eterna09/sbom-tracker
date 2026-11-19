from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.identity import Organization

if TYPE_CHECKING:
    from app.models.components import Component

class Product(Base):
    __tablename__ = "products"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(200))

    organization: Mapped[Organization] = relationship()
    versions: Mapped[list["ProductVersion"]] = relationship(back_populates="product")


class ProductVersion(Base):
    __tablename__ = "product_versions"
    __table_args__ = (UniqueConstraint("product_id", "version"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id", ondelete="CASCADE"))
    version: Mapped[str] = mapped_column(String(100))
    sbom_uploaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    product: Mapped[Product] = relationship(back_populates="versions")
    components: Mapped[list["Component"]] = relationship(secondary="version_components")