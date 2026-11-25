from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.service import AuditAction, attempted_email
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


def failed_logins_for(session: Session, email: str, limit: int = 100) -> list[AuditLog]:
    """Failed login attempts against one account, newest first (for incident investigation)."""
    return list(
        session.scalars(
            select(AuditLog)
            .where(
                AuditLog.action == AuditAction.LOGIN_FAILED.value,
                AuditLog.details.contains({"email": attempted_email(email)}),
            )
            .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
            .limit(limit)
        )
    )
