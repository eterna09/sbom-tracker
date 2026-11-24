import logging

import pytest

from app.auth.rate_limit import LoginRateLimiter
from tests.helpers import TEST_REDIS_URL, needs_redis


def test_attempts_beyond_the_account_limit_are_refused() -> None:
    limiter = LoginRateLimiter("memory://")

    allowed = [limiter.allows("10.0.0.1", "admin@acme.example") for _ in range(6)]

    assert allowed == [True, True, True, True, True, False]


@needs_redis
def test_limiters_in_different_processes_share_their_counters() -> None:
    assert TEST_REDIS_URL is not None
    first_process = LoginRateLimiter(TEST_REDIS_URL)
    second_process = LoginRateLimiter(TEST_REDIS_URL)
    first_process.reset()

    for _ in range(5):
        assert first_process.allows("10.0.0.1", "admin@acme.example")

    assert second_process.allows("10.0.0.1", "admin@acme.example") is False
    first_process.reset()


def test_unavailable_storage_allows_the_attempt_and_logs_an_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    limiter = LoginRateLimiter("redis://127.0.0.1:1/0")

    with caplog.at_level(logging.ERROR, logger="app.auth.rate_limit"):
        assert limiter.allows("10.0.0.1", "admin@acme.example") is True

    assert any(record.levelname == "ERROR" for record in caplog.records)
