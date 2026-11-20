from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.auth.tokens import InvalidAccessTokenError, create_access_token, read_user_id

SECRET = "test-secret-key-that-is-long-enough-for-hs256"
ONE_HOUR = timedelta(hours=1)


def test_token_round_trip_returns_the_user_id() -> None:
    token = create_access_token(7, SECRET, ONE_HOUR)

    assert read_user_id(token, SECRET) == 7


def test_token_signed_with_another_secret_is_rejected() -> None:
    forged = create_access_token(7, "attacker-secret-key-that-is-also-long-enough", ONE_HOUR)

    with pytest.raises(InvalidAccessTokenError):
        read_user_id(forged, SECRET)


def test_expired_token_is_rejected() -> None:
    expired = create_access_token(7, SECRET, timedelta(seconds=-1))

    with pytest.raises(InvalidAccessTokenError):
        read_user_id(expired, SECRET)


def test_unsigned_token_is_rejected() -> None:
    now = datetime.now(UTC)
    unsigned = jwt.encode({"sub": "7", "iat": now, "exp": now + ONE_HOUR}, None, algorithm="none")

    with pytest.raises(InvalidAccessTokenError):
        read_user_id(unsigned, SECRET)


def test_malformed_token_is_rejected() -> None:
    with pytest.raises(InvalidAccessTokenError):
        read_user_id("not-a-token", SECRET)
