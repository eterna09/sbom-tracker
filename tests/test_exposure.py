from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import FindingStatus, Organization, ProductVersion, User
from tests.helpers import add_finding, add_product_version, bearer_header

JANUARY = datetime(2026, 1, 1, tzinfo=UTC)
FEBRUARY = datetime(2026, 2, 1, tzinfo=UTC)


def _uploaded(
    session: Session, organization: Organization, name: str, at: datetime = JANUARY
) -> ProductVersion:
    version = add_product_version(session, organization, name)
    version.sbom_uploaded_at = at
    session.flush()
    return version


def _exposure(client: TestClient, organization: Organization, user: User) -> list[dict]:
    response = client.get(
        f"/organizations/{organization.id}/exposure", headers=bearer_header(user.id)
    )
    assert response.status_code == 200
    return response.json()


def test_counts_only_open_findings_by_severity_and_exploitation(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    version = _uploaded(session, acme, "Pump Controller")
    add_finding(session, version, "GHSA-0001", severity="high")
    add_finding(
        session,
        version,
        "GHSA-0002",
        severity="critical",
        known_exploited=True,
        status=FindingStatus.AFFECTED,
    )
    add_finding(session, version, "GHSA-0003", severity="high", status=FindingStatus.FIXED)
    add_finding(
        session, version, "GHSA-0004", severity="critical", status=FindingStatus.NOT_AFFECTED
    )

    [summary] = _exposure(client, acme, viewer)

    assert summary == {
        "product_id": version.product_id,
        "product_name": "Pump Controller",
        "latest_version": "1.0",
        "open_findings": 2,
        "open_critical": 1,
        "open_high": 1,
        "open_known_exploited": 1,
    }


def test_only_the_latest_uploaded_version_counts(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    old = _uploaded(session, acme, "Pump Controller", at=JANUARY)
    add_finding(session, old, "GHSA-0001")
    new = ProductVersion(product_id=old.product_id, version="2.0", sbom_uploaded_at=FEBRUARY)
    session.add(new)
    session.flush()

    [summary] = _exposure(client, acme, viewer)

    assert summary["latest_version"] == "2.0"
    assert summary["open_findings"] == 0


def test_product_without_sbom_is_listed_with_zeros(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    add_product_version(session, acme, "Pump Controller")

    [summary] = _exposure(client, acme, viewer)

    assert summary["latest_version"] is None
    assert summary["open_findings"] == 0


def test_products_with_exploited_findings_come_first(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    calm = _uploaded(session, acme, "A Calm Product")
    add_finding(session, calm, "GHSA-0001", severity="critical")
    urgent = _uploaded(session, acme, "Z Urgent Product")
    add_finding(session, urgent, "GHSA-KEV1", known_exploited=True)

    names = [summary["product_name"] for summary in _exposure(client, acme, viewer)]

    assert names == ["Z Urgent Product", "A Calm Product"]


def test_other_organisations_products_are_not_included(
    client: TestClient, session: Session, acme: Organization, viewer: User, outsider: User
) -> None:
    globex = session.get(Organization, outsider.memberships[0].organization_id)
    assert globex is not None
    add_finding(session, _uploaded(session, globex, "Globex Router"), "GHSA-0001")

    assert _exposure(client, acme, viewer) == []


def test_non_member_gets_404(client: TestClient, acme: Organization, outsider: User) -> None:
    response = client.get(f"/organizations/{acme.id}/exposure", headers=bearer_header(outsider.id))

    assert response.status_code == 404
