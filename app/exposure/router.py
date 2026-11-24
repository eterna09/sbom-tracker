from fastapi import APIRouter
from pydantic import BaseModel

from app.auth.access import CurrentAccess
from app.db import SessionDep
from app.exposure.queries import exposure_summary

router = APIRouter(prefix="/organizations/{organization_id}/exposure", tags=["exposure"])


class ProductExposureOut(BaseModel):
    product_id: int
    product_name: str
    latest_version: str | None
    open_findings: int
    open_critical: int
    open_high: int
    open_known_exploited: int


@router.get("", summary="Open findings per product (latest uploaded version), most exposed first")
def get_exposure(access: CurrentAccess, session: SessionDep) -> list[ProductExposureOut]:
    rows = exposure_summary(session, access.organization.id)
    return [ProductExposureOut.model_validate(dict(row)) for row in rows]
