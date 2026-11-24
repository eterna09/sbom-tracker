import logging
from functools import lru_cache
from typing import Annotated, Protocol

import redis
from fastapi import Depends

from app.config import get_settings

logger = logging.getLogger(__name__)


class Cache(Protocol):
    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str, ttl_seconds: int) -> None: ...

    def delete(self, key: str) -> None: ...


class RedisCache:
    """Cache backed by Redis or Valkey. Failures are logged and treated as cache misses."""

    def __init__(self, client: redis.Redis) -> None:
        self._client = client

    def get(self, key: str) -> str | None:
        try:
            return self._client.get(key)
        except redis.RedisError:
            logger.warning("Cache read failed for %s", key, exc_info=True)
            return None

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        try:
            self._client.set(key, value, ex=ttl_seconds)
        except redis.RedisError:
            logger.warning("Cache write failed for %s", key, exc_info=True)

    def delete(self, key: str) -> None:
        try:
            self._client.delete(key)
        except redis.RedisError:
            logger.warning("Cache delete failed for %s", key, exc_info=True)


class NullCache:
    """Used when no cache is configured: nothing is stored, every read is a miss."""

    def get(self, key: str) -> str | None:
        return None

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        return None

    def delete(self, key: str) -> None:
        return None


@lru_cache
def get_cache() -> Cache:
    return cache_from_url(get_settings().redis_url)


def cache_from_url(url: str | None) -> Cache:
    """Build the cache for a URL; a missing or empty URL means: run without a cache."""
    if not url:
        return NullCache()
    client = redis.Redis.from_url(
        url, decode_responses=True, socket_timeout=0.5, socket_connect_timeout=0.5
    )
    return RedisCache(client)


CacheDep = Annotated[Cache, Depends(get_cache)]
