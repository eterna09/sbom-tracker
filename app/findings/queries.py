from dataclasses import dataclass

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.models import Component, Finding, FindingStatus, Product, ProductVersion, Vulnerability

FindingRow = tuple[Finding, ProductVersion, Product, Component, Vulnerability]

_MOST_URGENT_FIRST = (
    Vulnerability.is_known_exploited.desc(),
    Finding.created_at.desc(),
    Finding.id.desc(),  # tie-breaker: one upload's findings share created_at
)


@dataclass(frozen=True)
class FindingFilters:
    """Optional filters for the findings list; None means "don't filter on this"."""

    status: FindingStatus | None = None
    product_id: int | None = None
    known_exploited: bool | None = None


@dataclass(frozen=True)
class PageRequest:
    limit: int
    offset: int


@dataclass(frozen=True)
class FindingPage:
    rows: list[FindingRow]
    total: int


def list_findings(
    session: Session, organization_id: int, filters: FindingFilters, page: PageRequest
) -> FindingPage:
    """Return one page of the organisation's findings, most urgent first, plus the total."""
    query = _apply_filters(_findings_of(organization_id), filters)
    total = session.scalar(query.with_only_columns(func.count(Finding.id))) or 0
    rows = session.execute(
        query.order_by(*_MOST_URGENT_FIRST).limit(page.limit).offset(page.offset)
    ).all()
    return FindingPage(rows=list(rows), total=total)


def _findings_of(organization_id: int) -> Select:
    return (
        select(Finding, ProductVersion, Product, Component, Vulnerability)
        .join(ProductVersion, Finding.product_version_id == ProductVersion.id)
        .join(Product, ProductVersion.product_id == Product.id)
        .join(Component, Finding.component_id == Component.id)
        .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
        .where(Product.organization_id == organization_id)
    )


def _apply_filters(query: Select, filters: FindingFilters) -> Select:
    if filters.status is not None:
        query = query.where(Finding.status == filters.status)
    if filters.product_id is not None:
        query = query.where(Product.id == filters.product_id)
    if filters.known_exploited is not None:
        query = query.where(Vulnerability.is_known_exploited == filters.known_exploited)
    return query
