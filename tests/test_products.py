import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Organization, Role, User
from tests.helpers import add_member, bearer_header


@pytest.fixture
def acme(session: Session) -> Organization:
    organization = Organization(name="Acme Machines")
    session.add(organization)
    session.flush()
    return organization


@pytest.fixture
def admin(session: Session, acme: Organization) -> User:
    return add_member(session, acme, "admin@acme.example", Role.ADMIN)


@pytest.fixture
def viewer(session: Session, acme: Organization) -> User:
    return add_member(session, acme, "viewer@acme.example", Role.VIEWER)


@pytest.fixture
def outsider(session: Session) -> User:
    globex = Organization(name="Globex")
    session.add(globex)
    session.flush()
    return add_member(session, globex, "admin@globex.example", Role.ADMIN)


def products_url(organization_id: int) -> str:
    return f"/organizations/{organization_id}/products"


def create_product(client: TestClient, organization_id: int, user: User, name: str) -> int:
    response = client.post(
        products_url(organization_id), json={"name": name}, headers=bearer_header(user.id)
    )
    return response.json()["id"]


def test_admin_creates_a_product(client: TestClient, acme: Organization, admin: User) -> None:
    response = client.post(
        products_url(acme.id), json={"name": "Pump Controller"}, headers=bearer_header(admin.id)
    )

    assert response.status_code == 201
    assert response.json()["name"] == "Pump Controller"


def test_any_member_lists_the_organizations_products(
    client: TestClient, acme: Organization, admin: User, viewer: User
) -> None:
    create_product(client, acme.id, admin, "Pump Controller")

    response = client.get(products_url(acme.id), headers=bearer_header(viewer.id))

    assert response.status_code == 200
    assert [product["name"] for product in response.json()] == ["Pump Controller"]


def test_viewer_cannot_create_a_product(
    client: TestClient, acme: Organization, viewer: User
) -> None:
    response = client.post(
        products_url(acme.id), json={"name": "Pump Controller"}, headers=bearer_header(viewer.id)
    )

    assert response.status_code == 403


def test_outsider_cannot_tell_that_the_organization_exists(
    client: TestClient, acme: Organization, outsider: User
) -> None:
    response = client.get(products_url(acme.id), headers=bearer_header(outsider.id))

    assert response.status_code == 404


def test_outsider_cannot_create_products_in_another_organization(
    client: TestClient, acme: Organization, outsider: User
) -> None:
    response = client.post(
        products_url(acme.id), json={"name": "Trojan"}, headers=bearer_header(outsider.id)
    )

    assert response.status_code == 404


def test_request_without_token_is_rejected(client: TestClient, acme: Organization) -> None:
    response = client.get(products_url(acme.id))

    assert response.status_code == 401


def test_duplicate_product_name_is_a_conflict(
    client: TestClient, acme: Organization, admin: User
) -> None:
    create_product(client, acme.id, admin, "Pump Controller")

    response = client.post(
        products_url(acme.id), json={"name": "Pump Controller"}, headers=bearer_header(admin.id)
    )

    assert response.status_code == 409


def test_empty_product_name_is_rejected(
    client: TestClient, acme: Organization, admin: User
) -> None:
    response = client.post(
        products_url(acme.id), json={"name": ""}, headers=bearer_header(admin.id)
    )

    assert response.status_code == 422


def test_admin_adds_a_version_to_a_product(
    client: TestClient, acme: Organization, admin: User
) -> None:
    product_id = create_product(client, acme.id, admin, "Pump Controller")

    response = client.post(
        f"{products_url(acme.id)}/{product_id}/versions",
        json={"version": "2.1.0"},
        headers=bearer_header(admin.id),
    )

    assert response.status_code == 201
    assert response.json()["version"] == "2.1.0"
    assert response.json()["sbom_uploaded_at"] is None


def test_duplicate_version_is_a_conflict(
    client: TestClient, acme: Organization, admin: User
) -> None:
    product_id = create_product(client, acme.id, admin, "Pump Controller")
    url = f"{products_url(acme.id)}/{product_id}/versions"
    client.post(url, json={"version": "2.1.0"}, headers=bearer_header(admin.id))

    response = client.post(url, json={"version": "2.1.0"}, headers=bearer_header(admin.id))

    assert response.status_code == 409


def test_product_of_another_organization_is_not_found_through_own_organization(
    client: TestClient, acme: Organization, admin: User, outsider: User
) -> None:
    acme_product_id = create_product(client, acme.id, admin, "Pump Controller")
    globex_id = outsider.memberships[0].organization_id

    response = client.get(
        f"{products_url(globex_id)}/{acme_product_id}/versions", headers=bearer_header(outsider.id)
    )

    assert response.status_code == 404
