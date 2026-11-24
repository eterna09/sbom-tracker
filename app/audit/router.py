from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel

from app.audit.queries import list_audit_entries
from app.auth.access import AdminAccess
from app.db import SessionDep
from app.models import AuditLog
from app.pagination import PageRequest

router = APIRouter(prefix="/organizations/{organization_id}/audit-log", tags=["audit log"])


class AuditEntryOut(BaseModel):
    id: int
    action: str
    user_id: int | None
    api_key_id: int | None
    target_type: str | None
    target_id: int | None
    details: dict[str, Any] | None
    occurred_at: datetime


class AuditPageOut(BaseModel):
    items: list[AuditEntryOut]
    total: int
    limit: int
    offset: int


def _to_out(entry: AuditLog) -> AuditEntryOut:
    return AuditEntryOut(
        id=entry.id,
        action=entry.action,
        user_id=entry.user_id,
        api_key_id=entry.api_key_id,
        target_type=entry.target_type,
        target_id=entry.target_id,
        details=entry.details,
        occurred_at=entry.occurred_at,
    )


@router.get("", summary="Read the organisation's audit log, newest first (admin)")
def get_audit_log(
    access: AdminAccess,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditPageOut:
    page = list_audit_entries(
        session, access.organization.id, PageRequest(limit=limit, offset=offset)
    )
    return AuditPageOut(
        items=[_to_out(entry) for entry in page.entries],
        total=page.total,
        limit=limit,
        offset=offset,
    )
