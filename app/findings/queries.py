from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Component, Finding, FindingStatus, Product, ProductVersion, Vulnerability

FindingRow = tuple[Finding, ProductVersion, Product, Component, Vulnerability]


@dataclass(frozen=True)
class FindingPage:
    rows: list[FindingRow]
    total: int


def list_findings(
    session: Session,
    organization_id: int,
    status: FindingStatus | None,
    product_id: int | None,
    known_exploited: bool | None,
    limit: int,
    offset: int,
) -> FindingPage:
    query = (
        select(Finding, ProductVersion, Product, Component, Vulnerability)
        .join(ProductVersion, Finding.product_version_id == ProductVersion.id)
        .join(Product, ProductVersion.product_id == Product.id)
        .join(Component, Finding.component_id == Component.id)
        .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
        .where(Product.organization_id == organization_id)
    )
    if status is not None:
        query = query.where(Finding.status == status)
    if product_id is not None:
        query = query.where(Product.id == product_id)
    if known_exploited is not None:
        query = query.where(Vulnerability.is_known_exploited == known_exploited)
    total = session.scalar(query.with_only_columns(func.count(Finding.id))) or 0
    rows = session.execute(
        query.order_by(
            Vulnerability.is_known_exploited.desc(),
            Finding.created_at.desc(),
            Finding.id.desc(),
        )
        .limit(limit)
        .offset(offset)
    ).tuples()
    return FindingPage(rows=list(rows), total=total)
