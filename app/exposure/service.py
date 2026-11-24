from pydantic import TypeAdapter
from sqlalchemy.orm import Session

from app.cache import Cache
from app.exposure.queries import exposure_summary
from app.exposure.schemas import ProductExposureOut

EXPOSURE_TTL_SECONDS = 300

_SUMMARY = TypeAdapter(list[ProductExposureOut])


def get_exposure_summary(
    session: Session, cache: Cache, organization_id: int
) -> list[ProductExposureOut]:
    """Return the organisation's exposure summary, from the cache when possible (cache-aside)."""
    key = _cache_key(organization_id)
    cached = cache.get(key)
    if cached is not None:
        return _SUMMARY.validate_json(cached)
    summary = [
        ProductExposureOut.model_validate(dict(row))
        for row in exposure_summary(session, organization_id)
    ]
    cache.set(key, _SUMMARY.dump_json(summary).decode(), EXPOSURE_TTL_SECONDS)
    return summary


def invalidate_exposure(cache: Cache, organization_id: int) -> None:
    """Forget the cached summary; call after committing a change that affects it."""
    cache.delete(_cache_key(organization_id))


def _cache_key(organization_id: int) -> str:
    return f"exposure:{organization_id}"
