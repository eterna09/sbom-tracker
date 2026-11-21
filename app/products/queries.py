from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Product


def get_product_in_organization(session: Session, product_id: int, organization_id: int) -> Product:
    """Return the product only if it belongs to the organisation; otherwise 404 (IDOR protection)."""
    product = session.scalar(
        select(Product).where(Product.id == product_id, Product.organization_id == organization_id)
    )
    if product is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")
    return product
