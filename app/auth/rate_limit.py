import logging
from typing import Annotated

import redis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from limits import RateLimitItem, RateLimitItemPerMinute
from limits.storage import storage_from_string
from limits.strategies import MovingWindowRateLimiter

from app.config import get_settings

logger = logging.getLogger(__name__)

_PER_CLIENT = RateLimitItemPerMinute(10)
_PER_ACCOUNT = RateLimitItemPerMinute(5)


class LoginRateLimiter:
    """Moving-window login limits per client and per account, in shared or local storage."""

    def __init__(self, storage_url: str) -> None:
        self._storage = storage_from_string(storage_url)
        self._limiter = MovingWindowRateLimiter(self._storage)

    def allows(self, client: str, account: str) -> bool:
        client_allowed = self._hit(_PER_CLIENT, "login-client", client)
        account_allowed = self._hit(_PER_ACCOUNT, "login-account", account)
        return client_allowed and account_allowed

    def reset(self) -> None:
        self._storage.reset()

    def _hit(self, item: RateLimitItem, *identifiers: str) -> bool:
        try:
            return self._limiter.hit(item, *identifiers)
        except redis.RedisError:
            logger.error("Rate limit storage unavailable; allowing the attempt", exc_info=True)
            return True


_login_limiter = LoginRateLimiter(get_settings().rate_limit_storage_url)


def limit_login_attempts(
    request: Request, form: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> None:
    """Reject login attempts beyond the per-client and per-account limits with 429."""
    client = request.client.host if request.client else "unknown"
    if not _login_limiter.allows(client, form.username.lower()):
        logger.warning("login rate limit exceeded", extra={"client": client})
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts, try again later",
            headers={"Retry-After": "60"},
        )


def reset_login_attempts() -> None:
    """Forget all recorded attempts (used by the tests)."""
    _login_limiter.reset()
