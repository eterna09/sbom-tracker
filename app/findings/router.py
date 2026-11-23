from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel

from app.auth.access import CurrentAccess
from app.db import SessionDep
from app.findings.queries import FindingFilters, FindingRow, PageRequest, list_findings
from app.models import FindingStatus

router = APIRouter(prefix="/organizations/{organization_id}/findings", tags=["findings"])


class FindingOut(BaseModel):
    id: int
    status: FindingStatus
    product_id: int
    product_name: str
    version: str
    component_ecosystem: str
    component_name: str
    component_version: str
    osv_id: str
    severity: str | None
    known_exploited: bool
    created_at: datetime


class FindingPageOut(BaseModel):
    items: list[FindingOut]
    total: int
    limit: int
    offset: int


def _to_out(row: FindingRow) -> FindingOut:
    finding, product_version, product, component, vulnerability = row
    return FindingOut(
        id=finding.id,
        status=finding.status,
        product_id=product.id,
        product_name=product.name,
        version=product_version.version,
        component_ecosystem=component.ecosystem,
        component_name=component.name,
        component_version=component.version,
        osv_id=vulnerability.osv_id,
        severity=vulnerability.severity,
        known_exploited=vulnerability.is_known_exploited,
        created_at=finding.created_at,
    )


@router.get("", summary="List the organisation's findings, most urgent first (paginated)")
def get_findings(
    access: CurrentAccess,
    session: SessionDep,
    status: FindingStatus | None = None,
    product_id: int | None = None,
    known_exploited: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FindingPageOut:
    findings = list_findings(
        session,
        access.organization.id,
        FindingFilters(status=status, product_id=product_id, known_exploited=known_exploited),
        PageRequest(limit=limit, offset=offset),
    )
    return FindingPageOut(
        items=[_to_out(row) for row in findings.rows],
        total=findings.total,
        limit=limit,
        offset=offset,
    )
