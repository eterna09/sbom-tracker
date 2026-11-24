from collections.abc import Iterator

import pytest
import redis
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.cache import NullCache, RedisCache, cache_from_url


class CacheTestSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    test_redis_url: str | None = None


TEST_REDIS_URL = CacheTestSettings().test_redis_url
needs_redis = pytest.mark.skipif(TEST_REDIS_URL is None, reason="TEST_REDIS_URL is not set")


@pytest.fixture
def client() -> Iterator[redis.Redis]:
    assert TEST_REDIS_URL is not None
    client = redis.Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    client.flushdb()
    yield client
    client.flushdb()


@needs_redis
def test_stored_value_is_returned(client: redis.Redis) -> None:
    cache = RedisCache(client)

    cache.set("exposure:1", "[]", ttl_seconds=60)

    assert cache.get("exposure:1") == "[]"


@needs_redis
def test_stored_value_expires_after_its_ttl(client: redis.Redis) -> None:
    RedisCache(client).set("exposure:1", "[]", ttl_seconds=60)

    assert 0 < client.ttl("exposure:1") <= 60


@needs_redis
def test_deleted_value_is_gone(client: redis.Redis) -> None:
    cache = RedisCache(client)
    cache.set("exposure:1", "[]", ttl_seconds=60)

    cache.delete("exposure:1")

    assert cache.get("exposure:1") is None


def test_unreachable_cache_behaves_like_an_empty_cache() -> None:
    unreachable = redis.Redis.from_url(
        "redis://127.0.0.1:1/0", socket_connect_timeout=0.2, decode_responses=True
    )
    cache = RedisCache(unreachable)

    cache.set("exposure:1", "[]", ttl_seconds=60)
    cache.delete("exposure:1")

    assert cache.get("exposure:1") is None


def test_null_cache_never_returns_a_value() -> None:
    cache = NullCache()

    cache.set("exposure:1", "[]", ttl_seconds=60)

    assert cache.get("exposure:1") is None


@pytest.mark.parametrize("url", [None, ""])
def test_missing_or_empty_url_means_no_cache(url: str | None) -> None:
    assert isinstance(cache_from_url(url), NullCache)


def test_configured_url_gives_a_redis_cache() -> None:
    assert isinstance(cache_from_url("redis://localhost:6379/0"), RedisCache)
