"""Create demo products with SBOMs and findings for load testing (local databases only)."""

import argparse

from sqlalchemy import select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import open_session
from app.matching.service import match_product_version
from app.models import Organization, Product, ProductVersion
from app.sboms.schemas import CycloneDxBom
from app.sboms.service import store_sbom
from app.seed import DEMO_ORGANIZATION_NAME

LOCAL_HOSTS = {"localhost", "127.0.0.1"}

OLD_PACKAGES = [
    "pkg:pypi/django@2.2.0",
    "pkg:pypi/jinja2@2.10.1",
    "pkg:pypi/requests@2.19.0",
    "pkg:pypi/flask@0.12.2",
    "pkg:pypi/pyyaml@5.1",
    "pkg:pypi/pillow@6.0.0",
    "pkg:pypi/urllib3@1.24.1",
    "pkg:pypi/werkzeug@0.15.3",
    "pkg:pypi/sqlalchemy@1.2.0",
    "pkg:pypi/cryptography@2.3",
    "pkg:pypi/lxml@4.2.0",
    "pkg:pypi/numpy@1.16.0",
]


def ensure_local_database(database_url: str) -> None:
    """Stop unless the database runs on this machine: load-test data never goes to production."""
    host = make_url(database_url).host
    if host not in LOCAL_HOSTS:
        raise SystemExit(f"Refusing to seed load-test data into a non-local database ({host})")


def _demo_bom() -> CycloneDxBom:
    components = [{"name": purl.split("/")[1].split("@")[0], "purl": purl} for purl in OLD_PACKAGES]
    return CycloneDxBom.model_validate(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}
    )


def _version_for(session: Session, organization: Organization, name: str) -> ProductVersion:
    product = session.scalar(
        select(Product).where(Product.organization_id == organization.id, Product.name == name)
    )
    if product is None:
        product = Product(organization_id=organization.id, name=name)
        session.add(product)
        session.flush()
    version = session.scalar(
        select(ProductVersion).where(
            ProductVersion.product_id == product.id, ProductVersion.version == "1.0"
        )
    )
    if version is None:
        version = ProductVersion(product=product, version="1.0")
        session.add(version)
        session.flush()
    return version


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--products", type=int, default=20)
    args = parser.parse_args()
    ensure_local_database(get_settings().database_url)
    bom = _demo_bom()
    with open_session() as session, session.begin():
        organization = session.scalar(
            select(Organization).where(Organization.name == DEMO_ORGANIZATION_NAME)
        )
        if organization is None:
            raise SystemExit("Run `python -m app.seed` first")
        findings = 0
        for number in range(1, args.products + 1):
            version = _version_for(session, organization, f"Load Test Product {number:02d}")
            store_sbom(session, version, bom)
            findings += match_product_version(session, version)
    print(f"Seeded {args.products} products; {findings} new findings")


if __name__ == "__main__":
    main()
