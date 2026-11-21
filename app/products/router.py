from datetime import datetime

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.access import AdminAccess, CurrentAccess
from app.db import SessionDep
from app.models import Product, ProductVersion

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


def _get_product(session: Session, product_id: int, organization_id: int) -> Product:
    product = session.scalar(
        select(Product).where(Product.id == product_id, Product.organization_id == organization_id)
    )
    if product is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")
    return product


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
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A product with this name already exists"
        ) from error
    return ProductOut(id=product.id, name=product.name)


@router.get("/{product_id}/versions", summary="List a product's versions")
def list_versions(product_id: int, access: CurrentAccess, session: SessionDep) -> list[VersionOut]:
    product = _get_product(session, product_id, access.organization.id)
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
    product = _get_product(session, product_id, access.organization.id)
    version = ProductVersion(product=product, version=payload.version)
    session.add(version)
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="This version already exists"
        ) from error
    return VersionOut(id=version.id, version=version.version, sbom_uploaded_at=None)
