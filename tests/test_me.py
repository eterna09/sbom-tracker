import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth.passwords import hash_password
from app.models import Membership, Organization, Role, User
from tests.helpers import bearer_header


@pytest.fixture
def analyst(session: Session) -> User:
    organization = Organization(name="Acme Machines")
    user = User(email="analyst@acme.example", password_hash=hash_password("irrelevant"))
    session.add(Membership(user=user, organization=organization, role=Role.ANALYST))
    session.flush()
    return user


def test_me_returns_the_calling_user_with_memberships(client: TestClient, analyst: User) -> None:
    response = client.get("/auth/me", headers=bearer_header(analyst.id))

    assert response.status_code == 200
    assert response.json() == {
        "id": analyst.id,
        "email": "analyst@acme.example",
        "memberships": [
            {
                "organization_id": analyst.memberships[0].organization_id,
                "organization_name": "Acme Machines",
                "role": "analyst",
            }
        ],
    }


def test_me_without_token_is_rejected(client: TestClient) -> None:
    response = client.get("/auth/me")

    assert response.status_code == 401


def test_me_with_invalid_token_is_rejected(client: TestClient) -> None:
    response = client.get("/auth/me", headers={"Authorization": "Bearer not-a-token"})

    assert response.status_code == 401


def test_me_with_token_of_deleted_user_is_rejected(client: TestClient) -> None:
    response = client.get("/auth/me", headers=bearer_header(user_id=999_999))

    assert response.status_code == 401
