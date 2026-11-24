import logging
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from limits import RateLimitItemPerMinute
from limits.storage import MemoryStorage
from limits.strategies import MovingWindowRateLimiter

logger = logging.getLogger(__name__)

_PER_CLIENT = RateLimitItemPerMinute(10)
_PER_ACCOUNT = RateLimitItemPerMinute(5)

_storage = MemoryStorage()
_limiter = MovingWindowRateLimiter(_storage)


def limit_login_attempts(
    request: Request, form: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> None:
    """Reject login attempts beyond the per-client and per-account limits with 429."""
    client = request.client.host if request.client else "unknown"
    client_allowed = _limiter.hit(_PER_CLIENT, "login-client", client)
    account_allowed = _limiter.hit(_PER_ACCOUNT, "login-account", form.username.lower())
    if not (client_allowed and account_allowed):
        logger.warning(
            "login rate limit exceeded",
            extra={"client": client, "account_limited": not account_allowed},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts, try again later",
            headers={"Retry-After": "60"},
        )


def reset_login_attempts() -> None:
    """Forget all recorded attempts (used by the tests)."""
    _storage.reset()
