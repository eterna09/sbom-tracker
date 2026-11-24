from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditLog
from app.pagination import PageRequest


@dataclass(frozen=True)
class AuditPage:
    entries: list[AuditLog]
    total: int


def list_audit_entries(session: Session, organization_id: int, page: PageRequest) -> AuditPage:
    """Return one page of the organisation's audit entries, newest first, plus the total."""
    query = select(AuditLog).where(AuditLog.organization_id == organization_id)
    total = session.scalar(query.with_only_columns(func.count(AuditLog.id))) or 0
    entries = session.scalars(
        query.order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
        .limit(page.limit)
        .offset(page.offset)
    ).all()
    return AuditPage(entries=list(entries), total=total)
