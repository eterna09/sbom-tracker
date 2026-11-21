from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.api_keys import hash_api_key
from app.auth.tokens import InvalidAccessTokenError, read_user_id
from app.config import Settings, get_settings
from app.db import get_session
from app.models import ApiKey, User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    try:
        user_id = read_user_id(token, settings.jwt_secret_key)
    except InvalidAccessTokenError as error:
        raise _unauthorized() from error
    user = session.get(User, user_id)
    if user is None:
        raise _unauthorized()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _invalid_api_key() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key"
    )


def get_current_api_key(
    raw_key: Annotated[str | None, Depends(api_key_header)],
    session: Annotated[Session, Depends(get_session)],
) -> ApiKey:
    if raw_key is None:
        raise _invalid_api_key()
    api_key = session.scalar(
        select(ApiKey).where(ApiKey.key_hash == hash_api_key(raw_key), ApiKey.revoked_at.is_(None))
    )
    if api_key is None:
        raise _invalid_api_key()
    return api_key


CurrentApiKey = Annotated[ApiKey, Depends(get_current_api_key)]
