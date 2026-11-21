from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.api_keys import generate_api_key, hash_api_key
from app.middleware import MAX_REQUEST_BYTES
from app.models import ApiKey, Component, Organization, Product, ProductVersion, User


@pytest.fixture
def ci_key(session: Session, acme: Organization) -> str:
    return _create_key(session, acme.id)


@pytest.fixture
def globex_ci_key(session: Session, outsider: User) -> str:
    return _create_key(session, outsider.memberships[0].organization_id)


@pytest.fixture
def pump_controller(session: Session, acme: Organization) -> Product:
    product = Product(organization_id=acme.id, name="Pump Controller")
    session.add(product)
    session.flush()
    return product


def _create_key(session: Session, organization_id: int) -> str:
    plaintext = generate_api_key()
    session.add(
        ApiKey(organization_id=organization_id, name="CI", key_hash=hash_api_key(plaintext))
    )
    session.flush()
    return plaintext


def cyclonedx(*purls: str | None) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [{"name": "component", "purl": purl} for purl in purls],
    }


def upload_url(product_id: int, version: str = "2.1.0") -> str:
    return f"/ci/products/{product_id}/versions/{version}/sbom"


def stored_component_names(session: Session, product_id: int, version: str) -> set[str]:
    session.expire_all()
    product_version = session.scalar(
        select(ProductVersion).where(
            ProductVersion.product_id == product_id, ProductVersion.version == version
        )
    )
    assert product_version is not None
    return {component.name for component in product_version.components}


def test_upload_stores_components_for_the_version(
    client: TestClient, session: Session, pump_controller: Product, ci_key: str
) -> None:
    response = client.put(
        upload_url(pump_controller.id),
        json=cyclonedx("pkg:pypi/jinja2@2.10.1", "pkg:npm/lodash@4.17.20"),
        headers={"X-API-Key": ci_key},
    )

    assert response.status_code == 200
    assert response.json() == {
        "product_id": pump_controller.id,
        "version": "2.1.0",
        "components_stored": 2,
        "components_skipped": 0,
    }
    assert stored_component_names(session, pump_controller.id, "2.1.0") == {"jinja2", "lodash"}


def test_upload_creates_the_version_and_records_the_upload_time(
    client: TestClient, session: Session, pump_controller: Product, ci_key: str
) -> None:
    client.put(
        upload_url(pump_controller.id, "3.0.0"),
        json=cyclonedx("pkg:pypi/jinja2@2.10.1"),
        headers={"X-API-Key": ci_key},
    )

    session.expire_all()
    version = session.scalar(select(ProductVersion).where(ProductVersion.version == "3.0.0"))
    assert version is not None
    assert version.sbom_uploaded_at is not None


def test_reupload_replaces_the_component_list(
    client: TestClient, session: Session, pump_controller: Product, ci_key: str
) -> None:
    headers = {"X-API-Key": ci_key}
    url = upload_url(pump_controller.id)
    client.put(
        url, json=cyclonedx("pkg:pypi/jinja2@2.10.1", "pkg:pypi/flask@2.0.0"), headers=headers
    )

    client.put(
        url, json=cyclonedx("pkg:pypi/flask@2.0.0", "pkg:pypi/requests@2.31.0"), headers=headers
    )

    assert stored_component_names(session, pump_controller.id, "2.1.0") == {"flask", "requests"}


def test_same_component_in_two_versions_is_stored_once(
    client: TestClient, session: Session, pump_controller: Product, ci_key: str
) -> None:
    headers = {"X-API-Key": ci_key}
    client.put(
        upload_url(pump_controller.id, "2.0.0"),
        json=cyclonedx("pkg:pypi/jinja2@2.10.1"),
        headers=headers,
    )
    client.put(
        upload_url(pump_controller.id, "2.1.0"),
        json=cyclonedx("pkg:pypi/jinja2@2.10.1"),
        headers=headers,
    )

    session.expire_all()
    assert session.scalar(select(func.count()).select_from(Component)) == 1


def test_components_without_usable_purl_are_skipped_and_counted(
    client: TestClient, pump_controller: Product, ci_key: str
) -> None:
    response = client.put(
        upload_url(pump_controller.id),
        json=cyclonedx("pkg:pypi/jinja2@2.10.1", None, "pkg:deb/debian/openssl@3.0.11"),
        headers={"X-API-Key": ci_key},
    )

    assert response.json()["components_stored"] == 1
    assert response.json()["components_skipped"] == 2


def test_upload_without_api_key_is_rejected(client: TestClient, pump_controller: Product) -> None:
    response = client.put(upload_url(pump_controller.id), json=cyclonedx())

    assert response.status_code == 401


def test_upload_with_unknown_api_key_is_rejected(
    client: TestClient, pump_controller: Product
) -> None:
    response = client.put(
        upload_url(pump_controller.id), json=cyclonedx(), headers={"X-API-Key": "sbom_made_up"}
    )

    assert response.status_code == 401


def test_upload_with_revoked_api_key_is_rejected(
    client: TestClient, session: Session, pump_controller: Product, ci_key: str
) -> None:
    api_key = session.scalar(select(ApiKey).where(ApiKey.key_hash == hash_api_key(ci_key)))
    assert api_key is not None
    api_key.revoked_at = datetime.now(UTC)
    session.flush()

    response = client.put(
        upload_url(pump_controller.id), json=cyclonedx(), headers={"X-API-Key": ci_key}
    )

    assert response.status_code == 401


def test_key_cannot_upload_to_another_organizations_product(
    client: TestClient, pump_controller: Product, globex_ci_key: str
) -> None:
    response = client.put(
        upload_url(pump_controller.id), json=cyclonedx(), headers={"X-API-Key": globex_ci_key}
    )

    assert response.status_code == 404


def test_non_cyclonedx_document_is_rejected(
    client: TestClient, pump_controller: Product, ci_key: str
) -> None:
    response = client.put(
        upload_url(pump_controller.id),
        json={"spdxVersion": "SPDX-2.3", "packages": []},
        headers={"X-API-Key": ci_key},
    )

    assert response.status_code == 422


def test_oversized_upload_is_rejected_before_processing(
    client: TestClient, pump_controller: Product, ci_key: str
) -> None:
    response = client.put(
        upload_url(pump_controller.id),
        content=b"x" * (MAX_REQUEST_BYTES + 1),
        headers={"X-API-Key": ci_key, "Content-Type": "application/json"},
    )

    assert response.status_code == 413
