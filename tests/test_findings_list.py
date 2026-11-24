from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import FindingStatus, Organization, User
from tests.helpers import add_finding, add_product_version, bearer_header


def _list(client: TestClient, organization: Organization, user: User, query: str = "") -> dict:
    response = client.get(
        f"/organizations/{organization.id}/findings{query}", headers=bearer_header(user.id)
    )
    assert response.status_code == 200
    return response.json()


def test_member_sees_the_organisations_findings(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    add_finding(session, add_product_version(session, acme), "GHSA-0001")

    page = _list(client, acme, viewer)

    assert page["total"] == 1
    item = page["items"][0]
    assert item["osv_id"] == "GHSA-0001"
    assert item["product_name"] == "Pump Controller"
    assert item["component_name"] == "pkg-ghsa-0001"
    assert item["status"] == "new"


def test_other_organisations_findings_are_not_listed(
    client: TestClient, session: Session, acme: Organization, viewer: User, outsider: User
) -> None:
    globex = session.get(Organization, outsider.memberships[0].organization_id)
    assert globex is not None
    add_finding(session, add_product_version(session, globex), "GHSA-0001")

    assert _list(client, acme, viewer)["total"] == 0


def test_non_member_gets_404(client: TestClient, acme: Organization, outsider: User) -> None:
    response = client.get(f"/organizations/{acme.id}/findings", headers=bearer_header(outsider.id))

    assert response.status_code == 404


def test_known_exploited_findings_come_first(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    version = add_product_version(session, acme)
    add_finding(session, version, "GHSA-0001")
    add_finding(session, version, "GHSA-KEV1", known_exploited=True)
    add_finding(session, version, "GHSA-0002")

    page = _list(client, acme, viewer)

    assert page["items"][0]["osv_id"] == "GHSA-KEV1"


def test_findings_can_be_filtered_by_status(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    version = add_product_version(session, acme)
    add_finding(session, version, "GHSA-0001")
    add_finding(session, version, "GHSA-0002", status=FindingStatus.INVESTIGATING)

    page = _list(client, acme, viewer, "?status=investigating")

    assert [item["osv_id"] for item in page["items"]] == ["GHSA-0002"]


def test_findings_can_be_filtered_by_known_exploited(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    version = add_product_version(session, acme)
    add_finding(session, version, "GHSA-0001")
    add_finding(session, version, "GHSA-KEV1", known_exploited=True)

    page = _list(client, acme, viewer, "?known_exploited=true")

    assert [item["osv_id"] for item in page["items"]] == ["GHSA-KEV1"]


def test_findings_can_be_filtered_by_product(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    add_finding(session, add_product_version(session, acme, "Pump Controller"), "GHSA-0001")
    press = add_product_version(session, acme, "Press Control Unit")
    add_finding(session, press, "GHSA-0002")

    page = _list(client, acme, viewer, f"?product_id={press.product_id}")

    assert [item["osv_id"] for item in page["items"]] == ["GHSA-0002"]


def test_pages_split_the_list_without_overlap(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    version = add_product_version(session, acme)
    for number in range(3):
        add_finding(session, version, f"GHSA-000{number}")

    first = _list(client, acme, viewer, "?limit=2&offset=0")
    second = _list(client, acme, viewer, "?limit=2&offset=2")

    assert first["total"] == second["total"] == 3
    assert len(first["items"]) == 2
    assert len(second["items"]) == 1
    first_ids = {item["id"] for item in first["items"]}
    second_ids = {item["id"] for item in second["items"]}
    assert first_ids.isdisjoint(second_ids)


def test_page_size_is_capped(client: TestClient, acme: Organization, viewer: User) -> None:
    response = client.get(
        f"/organizations/{acme.id}/findings?limit=101", headers=bearer_header(viewer.id)
    )

    assert response.status_code == 422
