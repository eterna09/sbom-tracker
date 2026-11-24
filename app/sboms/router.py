from typing import Annotated

from fastapi import APIRouter, Path
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentApiKey
from app.cache import CacheDep
from app.db import SessionDep
from app.exposure.service import invalidate_exposure
from app.matching.service import match_product_version
from app.models import Product, ProductVersion
from app.products.queries import get_product_in_organization
from app.sboms.schemas import CycloneDxBom
from app.sboms.service import store_sbom

router = APIRouter(prefix="/ci", tags=["ci"])

VersionName = Annotated[str, Path(min_length=1, max_length=100)]


class SbomUploadOut(BaseModel):
    product_id: int
    version: str
    components_stored: int
    components_skipped: int
    findings_created: int


def _get_or_create_version(session: Session, product: Product, name: str) -> ProductVersion:
    version = session.scalar(
        select(ProductVersion).where(
            ProductVersion.product_id == product.id, ProductVersion.version == name
        )
    )
    if version is None:
        version = ProductVersion(product=product, version=name)
        session.add(version)
    return version


@router.put(
    "/products/{product_id}/versions/{version}/sbom",
    summary="Upload the CycloneDX SBOM of a product version (API key)",
)
def upload_sbom(
    product_id: int,
    version: VersionName,
    bom: CycloneDxBom,
    api_key: CurrentApiKey,
    session: SessionDep,
    cache: CacheDep,
) -> SbomUploadOut:
    product = get_product_in_organization(session, product_id, api_key.organization_id)
    product_version = _get_or_create_version(session, product, version)
    result = store_sbom(session, product_version, bom)
    findings_created = match_product_version(session, product_version)
    session.commit()
    invalidate_exposure(cache, api_key.organization_id)
    return SbomUploadOut(
        product_id=product.id,
        version=version,
        components_stored=result.components_stored,
        components_skipped=result.components_skipped,
        findings_created=findings_created,
    )
