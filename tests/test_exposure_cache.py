from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth.api_keys import generate_api_key, hash_api_key
from app.models import (
    AffectedRange,
    ApiKey,
    FindingStatus,
    Organization,
    ProductVersion,
    Role,
    User,
    Vulnerability,
)
from tests.fakes import InMemoryCache
from tests.helpers import add_finding, add_member, add_product_version, bearer_header


def _uploaded(session: Session, organization: Organization, name: str) -> ProductVersion:
    version = add_product_version(session, organization, name)
    version.sbom_uploaded_at = datetime(2026, 1, 1, tzinfo=UTC)
    session.flush()
    return version


def _exposure(client: TestClient, organization: Organization, user: User) -> list[dict]:
    response = client.get(
        f"/organizations/{organization.id}/exposure", headers=bearer_header(user.id)
    )
    assert response.status_code == 200
    return response.json()


def test_summary_is_stored_in_the_cache(
    client: TestClient, session: Session, acme: Organization, viewer: User, cache: InMemoryCache
) -> None:
    _uploaded(session, acme, "Pump Controller")

    _exposure(client, acme, viewer)

    assert f"exposure:{acme.id}" in cache.values


def test_cached_summary_is_served_without_recomputing(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    version = _uploaded(session, acme, "Pump Controller")
    _exposure(client, acme, viewer)
    add_finding(session, version, "GHSA-0001")

    [summary] = _exposure(client, acme, viewer)

    assert summary["open_findings"] == 0


def test_triage_invalidates_the_summary(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    analyst = add_member(session, acme, "cache-analyst@acme.example", Role.ANALYST)
    version = _uploaded(session, acme, "Pump Controller")
    finding = add_finding(session, version, "GHSA-0001", status=FindingStatus.AFFECTED)
    assert _exposure(client, acme, viewer)[0]["open_findings"] == 1

    response = client.post(
        f"/organizations/{acme.id}/findings/{finding.id}/triage",
        json={"status": "fixed"},
        headers=bearer_header(analyst.id),
    )

    assert response.status_code == 200
    assert _exposure(client, acme, viewer)[0]["open_findings"] == 0


def test_sbom_upload_invalidates_the_summary(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    product_id = add_product_version(session, acme, "Pump Controller").product_id
    session.add(
        Vulnerability(
            osv_id="GHSA-h5c8-rqwp-cp95",
            affected_ranges=[
                AffectedRange(
                    ecosystem="PyPI",
                    package_name="jinja2",
                    introduced="0",
                    fixed="2.11.3",
                    last_affected=None,
                )
            ],
        )
    )
    key = generate_api_key()
    session.add(ApiKey(organization_id=acme.id, name="CI", key_hash=hash_api_key(key)))
    session.flush()
    assert _exposure(client, acme, viewer)[0]["latest_version"] is None

    client.put(
        f"/ci/products/{product_id}/versions/2.1.0/sbom",
        json={
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"name": "jinja2", "purl": "pkg:pypi/jinja2@2.10.1"}],
        },
        headers={"X-API-Key": key},
    )

    [summary] = _exposure(client, acme, viewer)
    assert summary["latest_version"] == "2.1.0"
    assert summary["open_findings"] == 1


def test_new_product_invalidates_the_summary(
    client: TestClient, session: Session, acme: Organization, viewer: User, admin: User
) -> None:
    _uploaded(session, acme, "Pump Controller")
    assert len(_exposure(client, acme, viewer)) == 1

    client.post(
        f"/organizations/{acme.id}/products",
        json={"name": "Press Control Unit"},
        headers=bearer_header(admin.id),
    )

    assert len(_exposure(client, acme, viewer)) == 2


def test_summaries_are_cached_per_organisation(
    client: TestClient, session: Session, acme: Organization, viewer: User, outsider: User
) -> None:
    globex = session.get(Organization, outsider.memberships[0].organization_id)
    assert globex is not None
    _uploaded(session, acme, "Pump Controller")
    _uploaded(session, globex, "Globex Router")

    acme_names = [summary["product_name"] for summary in _exposure(client, acme, viewer)]
    globex_names = [summary["product_name"] for summary in _exposure(client, globex, outsider)]

    assert acme_names == ["Pump Controller"]
    assert globex_names == ["Globex Router"]
