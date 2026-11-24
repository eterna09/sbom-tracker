import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Finding, FindingStatus, Organization, Role, User
from tests.helpers import add_finding, add_member, add_product_version, bearer_header


@pytest.fixture
def analyst(session: Session, acme: Organization) -> User:
    return add_member(session, acme, "triage-analyst@acme.example", Role.ANALYST)


def _triage(
    client: TestClient, organization: Organization, finding: Finding, user: User, body: dict
):
    return client.post(
        f"/organizations/{organization.id}/findings/{finding.id}/triage",
        json=body,
        headers=bearer_header(user.id),
    )


def _stored(session: Session, finding: Finding) -> Finding:
    session.expire_all()
    stored = session.get(Finding, finding.id)
    assert stored is not None
    return stored


def test_analyst_starts_investigating_a_new_finding(
    client: TestClient, session: Session, acme: Organization, analyst: User
) -> None:
    finding = add_finding(session, add_product_version(session, acme), "GHSA-0001")

    response = _triage(client, acme, finding, analyst, {"status": "investigating"})

    assert response.status_code == 200
    assert response.json()["status"] == "investigating"
    stored = _stored(session, finding)
    assert stored.status is FindingStatus.INVESTIGATING
    assert stored.triaged_by_id == analyst.id


def test_forbidden_transition_is_rejected_and_changes_nothing(
    client: TestClient, session: Session, acme: Organization, analyst: User
) -> None:
    finding = add_finding(session, add_product_version(session, acme), "GHSA-0001")

    response = _triage(client, acme, finding, analyst, {"status": "fixed"})

    assert response.status_code == 409
    assert _stored(session, finding).status is FindingStatus.NEW


@pytest.mark.parametrize("justification", [None, "", "   "])
def test_not_affected_requires_a_justification(
    client: TestClient,
    session: Session,
    acme: Organization,
    analyst: User,
    justification: str | None,
) -> None:
    finding = add_finding(
        session,
        add_product_version(session, acme),
        "GHSA-0001",
        status=FindingStatus.INVESTIGATING,
    )

    response = _triage(
        client,
        acme,
        finding,
        analyst,
        {"status": "not_affected", "justification": justification},
    )

    assert response.status_code == 422


def test_not_affected_stores_the_justification(
    client: TestClient, session: Session, acme: Organization, analyst: User
) -> None:
    finding = add_finding(
        session,
        add_product_version(session, acme),
        "GHSA-0001",
        status=FindingStatus.INVESTIGATING,
    )
    reason = "The vulnerable template filter is never used"

    response = _triage(
        client, acme, finding, analyst, {"status": "not_affected", "justification": reason}
    )

    assert response.status_code == 200
    assert _stored(session, finding).justification == reason


def test_viewer_cannot_triage(
    client: TestClient, session: Session, acme: Organization, viewer: User
) -> None:
    finding = add_finding(session, add_product_version(session, acme), "GHSA-0001")

    response = _triage(client, acme, finding, viewer, {"status": "investigating"})

    assert response.status_code == 403


def test_non_member_gets_404(
    client: TestClient, session: Session, acme: Organization, outsider: User
) -> None:
    finding = add_finding(session, add_product_version(session, acme), "GHSA-0001")

    response = _triage(client, acme, finding, outsider, {"status": "investigating"})

    assert response.status_code == 404


def test_finding_of_another_organisation_cannot_be_triaged_through_own_url(
    client: TestClient, session: Session, acme: Organization, analyst: User, outsider: User
) -> None:
    globex = session.get(Organization, outsider.memberships[0].organization_id)
    assert globex is not None
    foreign = add_finding(session, add_product_version(session, globex), "GHSA-0001")

    response = _triage(client, acme, foreign, analyst, {"status": "investigating"})

    assert response.status_code == 404
    assert _stored(session, foreign).status is FindingStatus.NEW
