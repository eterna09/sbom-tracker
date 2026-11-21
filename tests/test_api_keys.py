import hashlib

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.api_keys import generate_api_key, hash_api_key
from app.models import ApiKey, Organization, User
from tests.helpers import bearer_header


def api_keys_url(organization_id: int) -> str:
    return f"/organizations/{organization_id}/api-keys"


def test_generated_keys_are_prefixed_and_unique() -> None:
    first, second = generate_api_key(), generate_api_key()

    assert first.startswith("sbom_")
    assert first != second


def test_api_key_hash_is_sha256_of_the_key() -> None:
    assert hash_api_key("sbom_example") == hashlib.sha256(b"sbom_example").hexdigest()


def test_admin_creates_a_key_and_sees_it_once(
    client: TestClient, session: Session, acme: Organization, admin: User
) -> None:
    response = client.post(
        api_keys_url(acme.id), json={"name": "GitHub Actions"}, headers=bearer_header(admin.id)
    )

    assert response.status_code == 201
    body = response.json()
    assert body["key"].startswith("sbom_")
    assert "key_hash" not in body
    stored = session.scalar(select(ApiKey).where(ApiKey.id == body["id"]))
    assert stored is not None
    assert stored.key_hash == hash_api_key(body["key"])
    assert stored.key_hash != body["key"]


def test_listing_keys_never_shows_the_key(
    client: TestClient, acme: Organization, admin: User
) -> None:
    client.post(
        api_keys_url(acme.id), json={"name": "GitHub Actions"}, headers=bearer_header(admin.id)
    )

    response = client.get(api_keys_url(acme.id), headers=bearer_header(admin.id))

    assert response.status_code == 200
    assert [key["name"] for key in response.json()] == ["GitHub Actions"]
    assert all("key" not in key and "key_hash" not in key for key in response.json())


def test_viewer_cannot_manage_keys(client: TestClient, acme: Organization, viewer: User) -> None:
    headers = bearer_header(viewer.id)

    assert client.get(api_keys_url(acme.id), headers=headers).status_code == 403
    assert (
        client.post(api_keys_url(acme.id), json={"name": "x"}, headers=headers).status_code == 403
    )


def test_outsider_cannot_create_keys_for_another_organization(
    client: TestClient, acme: Organization, outsider: User
) -> None:
    response = client.post(
        api_keys_url(acme.id), json={"name": "Backdoor"}, headers=bearer_header(outsider.id)
    )

    assert response.status_code == 404


def test_admin_revokes_a_key(client: TestClient, acme: Organization, admin: User) -> None:
    headers = bearer_header(admin.id)
    key_id = client.post(api_keys_url(acme.id), json={"name": "Old CI"}, headers=headers).json()[
        "id"
    ]

    response = client.post(f"{api_keys_url(acme.id)}/{key_id}/revoke", headers=headers)

    assert response.status_code == 200
    assert response.json()["revoked_at"] is not None


def test_key_of_another_organization_cannot_be_revoked(
    client: TestClient, acme: Organization, admin: User, outsider: User
) -> None:
    acme_key_id = client.post(
        api_keys_url(acme.id), json={"name": "Acme CI"}, headers=bearer_header(admin.id)
    ).json()["id"]
    globex_id = outsider.memberships[0].organization_id

    response = client.post(
        f"{api_keys_url(globex_id)}/{acme_key_id}/revoke", headers=bearer_header(outsider.id)
    )

    assert response.status_code == 404
