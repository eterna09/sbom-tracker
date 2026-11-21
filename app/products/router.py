from datetime import datetime

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.access import AdminAccess, CurrentAccess
from app.db import SessionDep
from app.models import Product, ProductVersion
from app.products.queries import get_product_in_organization

router = APIRouter(prefix="/organizations/{organization_id}/products", tags=["products"])


class ProductCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class ProductOut(BaseModel):
    id: int
    name: str


class VersionCreate(BaseModel):
    version: str = Field(min_length=1, max_length=100)


class VersionOut(BaseModel):
    id: int
    version: str
    sbom_uploaded_at: datetime | None


def _commit_or_conflict(session: Session, detail: str) -> None:
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail) from error


@router.get("", summary="List the organisation's products")
def list_products(access: CurrentAccess, session: SessionDep) -> list[ProductOut]:
    products = session.scalars(
        select(Product)
        .where(Product.organization_id == access.organization.id)
        .order_by(Product.name)
    )
    return [ProductOut(id=product.id, name=product.name) for product in products]


@router.post("", status_code=status.HTTP_201_CREATED, summary="Create a product")
def create_product(payload: ProductCreate, access: AdminAccess, session: SessionDep) -> ProductOut:
    product = Product(organization_id=access.organization.id, name=payload.name)
    session.add(product)

    _commit_or_conflict(session, "A product with this name already exists")
    return ProductOut(id=product.id, name=product.name)


@router.get("/{product_id}/versions", summary="List a product's versions")
def list_versions(product_id: int, access: CurrentAccess, session: SessionDep) -> list[VersionOut]:
    product = get_product_in_organization(session, product_id, access.organization.id)
    return [
        VersionOut(
            id=version.id, version=version.version, sbom_uploaded_at=version.sbom_uploaded_at
        )
        for version in product.versions
    ]


@router.post(
    "/{product_id}/versions",
    status_code=status.HTTP_201_CREATED,
    summary="Add a version to a product",
)
def create_version(
    product_id: int, payload: VersionCreate, access: AdminAccess, session: SessionDep
) -> VersionOut:
    product = get_product_in_organization(session, product_id, access.organization.id)
    version = ProductVersion(product=product, version=payload.version)
    session.add(version)
    _commit_or_conflict(session, "This version already exists")
    return VersionOut(id=version.id, version=version.version, sbom_uploaded_at=None)
