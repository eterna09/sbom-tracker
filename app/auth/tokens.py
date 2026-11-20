from datetime import UTC, datetime, timedelta

import jwt

ALGORITHM = "HS256"


class InvalidAccessTokenError(Exception):
    """The token is expired, forged, unsigned or malformed."""


def create_access_token(user_id: int, secret_key: str, lifetime: timedelta) -> str:
    issued_at = datetime.now(UTC)
    claims = {"sub": str(user_id), "iat": issued_at, "exp": issued_at + lifetime}
    return jwt.encode(claims, secret_key, algorithm=ALGORITHM)


def read_user_id(token: str, secret_key: str) -> int:
    try:
        claims = jwt.decode(
            token,
            secret_key,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "iat", "exp"]},
        )
    except jwt.InvalidTokenError as error:
        raise InvalidAccessTokenError from error
    return int(claims["sub"])
