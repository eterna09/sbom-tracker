import enum
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.columns import value_enum
from app.models.components import Component
from app.models.identity import User
from app.models.products import ProductVersion
from app.models.vulnerabilities import Vulnerability


class FindingStatus(enum.StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("product_version_id", "component_id", "vulnerability_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    product_version_id: Mapped[int] = mapped_column(
        ForeignKey("product_versions.id", ondelete="CASCADE")
    )
    component_id: Mapped[int] = mapped_column(ForeignKey("components.id", ondelete="CASCADE"))
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE")
    )
    status: Mapped[FindingStatus] = mapped_column(
        value_enum(FindingStatus, "finding_status"),
        server_default=FindingStatus.NEW.value,
    )
    justification: Mapped[str | None] = mapped_column(Text)
    triaged_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    product_version: Mapped[ProductVersion] = relationship()
    component: Mapped[Component] = relationship()
    vulnerability: Mapped[Vulnerability] = relationship()
    triaged_by: Mapped[User | None] = relationship()
    report_case: Mapped["ReportCase | None"] = relationship(back_populates="finding")


class ReportCase(Base):
    __tablename__ = "report_cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), unique=True
    )
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    early_warning_due: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    notification_due: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    final_report_due: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    early_warning_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notification_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    final_report_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    finding: Mapped[Finding] = relationship(back_populates="report_case")
