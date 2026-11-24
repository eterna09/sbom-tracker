from fastapi import APIRouter

from app.auth.access import CurrentAccess
from app.cache import CacheDep
from app.db import SessionDep
from app.exposure.schemas import ProductExposureOut
from app.exposure.service import get_exposure_summary

router = APIRouter(prefix="/organizations/{organization_id}/exposure", tags=["exposure"])


@router.get("", summary="Open findings per product (latest uploaded version), most exposed first")
def get_exposure(
    access: CurrentAccess, session: SessionDep, cache: CacheDep
) -> list[ProductExposureOut]:
    return get_exposure_summary(session, cache, access.organization.id)
