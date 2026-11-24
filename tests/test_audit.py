from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.api_keys import generate_api_key, hash_api_key
from app.auth.passwords import hash_password
from app.models import ApiKey, AuditLog, Organization, Product, Role, User
from tests.helpers import add_finding, add_member, add_product_version, bearer_header

PASSWORD = "correct-horse-battery-staple"


def _entries(session: Session, action: str) -> list[AuditLog]:
    session.expire_all()
    return list(session.scalars(select(AuditLog).where(AuditLog.action == action)))


def test_successful_login_is_recorded(client: TestClient, session: Session) -> None:
    user = User(email="login@acme.example", password_hash=hash_password(PASSWORD))
    session.add(user)
    session.flush()

    client.post("/auth/token", data={"username": user.email, "password": PASSWORD})

    [entry] = _entries(session, "login.succeeded")
    assert entry.user_id == user.id


def test_failed_login_records_the_email_but_never_the_password(
    client: TestClient, session: Session
) -> None:
    client.post("/auth/token", data={"username": "Someone@Acme.example", "password": "guess-123"})

    [entry] = _entries(session, "login.failed")
    assert entry.user_id is None
    assert entry.details == {"email": "someone@acme.example"}
    assert "guess-123" not in str(entry.details)


def test_sbom_upload_is_recorded_with_the_api_key(
    client: TestClient, session: Session, acme: Organization
) -> None:
    product = Product(organization_id=acme.id, name="Pump Controller")
    key = generate_api_key()
    api_key = ApiKey(organization_id=acme.id, name="CI", key_hash=hash_api_key(key))
    session.add_all([product, api_key])
    session.flush()

    client.put(
        f"/ci/products/{product.id}/versions/2.1.0/sbom",
        json={
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"name": "jinja2", "purl": "pkg:pypi/jinja2@2.10.1"}],
        },
        headers={"X-API-Key": key},
    )

    [entry] = _entries(session, "sbom.uploaded")
    assert entry.organization_id == acme.id
    assert entry.api_key_id == api_key.id
    assert entry.target_type == "product_version"
    assert entry.details == {"components_stored": 1, "findings_created": 0}


def test_triage_is_recorded_with_old_and_new_status(
    client: TestClient, session: Session, acme: Organization
) -> None:
    analyst = add_member(session, acme, "audit-analyst@acme.example", Role.ANALYST)
    finding = add_finding(session, add_product_version(session, acme), "GHSA-0001")

    client.post(
        f"/organizations/{acme.id}/findings/{finding.id}/triage",
        json={"status": "investigating"},
        headers=bearer_header(analyst.id),
    )

    [entry] = _entries(session, "finding.triaged")
    assert (entry.user_id, entry.target_type, entry.target_id) == (
        analyst.id,
        "finding",
        finding.id,
    )
    assert entry.details == {"from": "new", "to": "investigating"}


def test_rejected_triage_is_not_recorded(
    client: TestClient, session: Session, acme: Organization
) -> None:
    analyst = add_member(session, acme, "audit-analyst@acme.example", Role.ANALYST)
    finding = add_finding(session, add_product_version(session, acme), "GHSA-0001")

    response = client.post(
        f"/organizations/{acme.id}/findings/{finding.id}/triage",
        json={"status": "fixed"},
        headers=bearer_header(analyst.id),
    )

    assert response.status_code == 409
    assert _entries(session, "finding.triaged") == []


def test_api_key_creation_is_recorded_without_the_key(
    client: TestClient, session: Session, acme: Organization, admin: User
) -> None:
    created = client.post(
        f"/organizations/{acme.id}/api-keys", json={"name": "CI"}, headers=bearer_header(admin.id)
    ).json()

    [entry] = _entries(session, "api_key.created")
    assert (entry.user_id, entry.api_key_id) == (admin.id, created["id"])
    assert created["key"] not in str(entry.details)


def test_api_key_revocation_is_recorded_once(
    client: TestClient, session: Session, acme: Organization, admin: User
) -> None:
    headers = bearer_header(admin.id)
    created = client.post(
        f"/organizations/{acme.id}/api-keys", json={"name": "CI"}, headers=headers
    ).json()
    url = f"/organizations/{acme.id}/api-keys/{created['id']}/revoke"

    client.post(url, headers=headers)
    client.post(url, headers=headers)

    assert len(_entries(session, "api_key.revoked")) == 1
