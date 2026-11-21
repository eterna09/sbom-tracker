from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.matching.rematch import rematch_all
from app.matching.service import match_product_version
from app.models import (
    AffectedRange,
    Component,
    Finding,
    Organization,
    Product,
    ProductVersion,
    Vulnerability,
)


def _vulnerability(
    osv_id: str = "GHSA-h5c8-rqwp-cp95",
    package_name: str = "jinja2",
    ranges: tuple[tuple[str, str], ...] = (("0", "2.11.3"),),
) -> Vulnerability:
    return Vulnerability(
        osv_id=osv_id,
        affected_ranges=[
            AffectedRange(
                ecosystem="PyPI",
                package_name=package_name,
                introduced=introduced,
                fixed=fixed,
                last_affected=None,
            )
            for introduced, fixed in ranges
        ],
    )


def _product_version(
    session: Session, organization: Organization, components: list[Component]
) -> ProductVersion:
    product = Product(organization_id=organization.id, name="Press control unit")
    session.add(product)
    session.flush()
    version = ProductVersion(product_id=product.id, version="1.0")
    version.components = components
    session.add(version)
    session.flush()
    return version


def _findings(session: Session, version: ProductVersion) -> list[Finding]:
    return list(session.scalars(select(Finding).where(Finding.product_version_id == version.id)))


def test_affected_component_gets_a_finding(session: Session, acme: Organization) -> None:
    vulnerability = _vulnerability()
    session.add(vulnerability)
    component = Component(ecosystem="PyPI", name="jinja2", version="2.10.1")
    version = _product_version(session, acme, [component])

    created = match_product_version(session, version)

    assert created == 1
    assert [(f.component_id, f.vulnerability_id) for f in _findings(session, version)] == [
        (component.id, vulnerability.id)
    ]


def test_fixed_component_gets_no_finding(session: Session, acme: Organization) -> None:
    session.add(_vulnerability())
    version = _product_version(
        session, acme, [Component(ecosystem="PyPI", name="jinja2", version="2.11.3")]
    )

    assert match_product_version(session, version) == 0
    assert _findings(session, version) == []


def test_component_names_are_normalised_before_matching(
    session: Session, acme: Organization
) -> None:
    session.add(_vulnerability())
    version = _product_version(
        session, acme, [Component(ecosystem="PyPI", name="Jinja2", version="2.10.1")]
    )

    assert match_product_version(session, version) == 1


def test_packages_only_match_within_their_ecosystem(session: Session, acme: Organization) -> None:
    session.add(_vulnerability())
    version = _product_version(
        session, acme, [Component(ecosystem="npm", name="jinja2", version="2.10.1")]
    )

    assert match_product_version(session, version) == 0


def test_two_hitting_ranges_give_one_finding(session: Session, acme: Organization) -> None:
    session.add(_vulnerability(ranges=(("0", "2.11.3"), ("2.0", "2.11.3"))))
    version = _product_version(
        session, acme, [Component(ecosystem="PyPI", name="jinja2", version="2.10.1")]
    )

    assert match_product_version(session, version) == 1
    assert len(_findings(session, version)) == 1


def test_matching_again_creates_no_duplicates(session: Session, acme: Organization) -> None:
    session.add(_vulnerability())
    version = _product_version(
        session, acme, [Component(ecosystem="PyPI", name="jinja2", version="2.10.1")]
    )
    match_product_version(session, version)

    assert match_product_version(session, version) == 0
    assert len(_findings(session, version)) == 1


def test_version_without_components_gets_no_findings(session: Session, acme: Organization) -> None:
    version = _product_version(session, acme, [])

    assert match_product_version(session, version) == 0


def test_components_not_yet_flushed_are_matched(session: Session, acme: Organization) -> None:
    session.add(_vulnerability())
    version = _product_version(session, acme, [])

    with session.no_autoflush:
        version.components = [Component(ecosystem="PyPI", name="jinja2", version="2.10.1")]
        assert match_product_version(session, version) == 1


def test_rematch_covers_only_versions_with_an_sbom(session: Session, acme: Organization) -> None:
    session.add(_vulnerability())
    with_sbom = _product_version(
        session, acme, [Component(ecosystem="PyPI", name="jinja2", version="2.10.1")]
    )
    with_sbom.sbom_uploaded_at = datetime.now(UTC)
    session.flush()

    assert rematch_all(session) == (1, 1)
