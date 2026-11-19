from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, false
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    osv_id: Mapped[str] = mapped_column(String(100), unique=True)
    summary: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(20))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_known_exploited: Mapped[bool] = mapped_column(server_default=false())
    kev_added_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    aliases: Mapped[list["VulnerabilityAlias"]] = relationship(
        back_populates="vulnerability"
    )
    affected_ranges: Mapped[list["AffectedRange"]] = relationship(
        back_populates="vulnerability"
    )


class VulnerabilityAlias(Base):
    __tablename__ = "vulnerability_aliases"
    __table_args__ = (UniqueConstraint("vulnerability_id", "alias"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE")
    )
    alias: Mapped[str] = mapped_column(String(100))

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="aliases")


class AffectedRange(Base):
    __tablename__ = "affected_ranges"

    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE")
    )
    ecosystem: Mapped[str] = mapped_column(String(50))
    package_name: Mapped[str] = mapped_column(String(255))
    introduced: Mapped[str | None] = mapped_column(String(100))
    fixed: Mapped[str | None] = mapped_column(String(100))
    last_affected: Mapped[str | None] = mapped_column(String(100))

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="affected_ranges")