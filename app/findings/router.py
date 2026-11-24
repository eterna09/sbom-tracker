from datetime import datetime
from typing import Annotated, Self

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, model_validator

from app.auth.access import AnalystAccess, CurrentAccess
from app.cache import CacheDep
from app.db import SessionDep
from app.exposure.service import invalidate_exposure
from app.findings.queries import (
    FindingFilters,
    FindingRow,
    PageRequest,
    get_finding,
    list_findings,
)
from app.findings.triage import InvalidTransitionError, triage
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
    justification: str | None
    triaged_by_id: int | None


class FindingPageOut(BaseModel):
    items: list[FindingOut]
    total: int
    limit: int
    offset: int


class TriageRequest(BaseModel):
    status: FindingStatus
    justification: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def _not_affected_needs_justification(self) -> Self:
        if self.status is FindingStatus.NOT_AFFECTED and not (self.justification or "").strip():
            raise ValueError("A justification is required to mark a finding as not affected")
        return self


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
        justification=finding.justification,
        triaged_by_id=finding.triaged_by_id,
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


@router.post("/{finding_id}/triage", summary="Move a finding to a new triage status (analyst)")
def triage_finding(
    finding_id: int,
    request: TriageRequest,
    access: AnalystAccess,
    session: SessionDep,
    cache: CacheDep,  # new
) -> FindingOut:
    row = get_finding(session, access.organization.id, finding_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    try:
        triage(row[0], request.status, request.justification, access.user)
    except InvalidTransitionError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
    session.commit()
    invalidate_exposure(cache, access.organization.id)  # new
    return _to_out(row)
