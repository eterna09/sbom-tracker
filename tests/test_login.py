import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth.passwords import hash_password
from app.auth.tokens import read_user_id
from app.config import get_settings
from app.models import User


@pytest.fixture
def alice(session: Session) -> User:
    user = User(email="alice@acme.example", password_hash=hash_password("alice-password"))
    session.add(user)
    session.flush()
    return user


def test_login_with_correct_credentials_returns_a_token_for_the_user(
    client: TestClient, alice: User
) -> None:
    response = client.post(
        "/auth/token", data={"username": "alice@acme.example", "password": "alice-password"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert read_user_id(body["access_token"], get_settings().jwt_secret_key) == alice.id


def test_login_with_wrong_password_is_rejected(client: TestClient, alice: User) -> None:
    response = client.post(
        "/auth/token", data={"username": "alice@acme.example", "password": "wrong"}
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect email or password"}


def test_login_with_unknown_email_gives_the_same_error(client: TestClient) -> None:
    response = client.post(
        "/auth/token", data={"username": "nobody@acme.example", "password": "whatever"}
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect email or password"}


def test_login_without_credentials_is_a_validation_error(client: TestClient) -> None:
    response = client.post("/auth/token", data={})

    assert response.status_code == 422
