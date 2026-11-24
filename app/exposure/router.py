from fastapi import APIRouter

from app.auth.access import CurrentAccess
from app.db import SessionDep
from app.exposure.queries import exposure_summary
from app.exposure.schemas import ProductExposureOut

router = APIRouter(prefix="/organizations/{organization_id}/exposure", tags=["exposure"])


@router.get("", summary="Open findings per product (latest uploaded version), most exposed first")
def get_exposure(access: CurrentAccess, session: SessionDep) -> list[ProductExposureOut]:
    rows = exposure_summary(session, access.organization.id)
    return [ProductExposureOut.model_validate(dict(row)) for row in rows]
