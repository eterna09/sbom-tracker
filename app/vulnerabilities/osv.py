from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any

_SEVERITY_LEVELS = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}
_VERSION_RANGE_TYPES = {"ECOSYSTEM", "SEMVER"}


@dataclass(frozen=True)
class AffectedRangeData:
    ecosystem: str
    package_name: str
    introduced: str | None
    fixed: str | None
    last_affected: str | None


@dataclass(frozen=True)
class OsvRecord:
    """One OSV vulnerability record, reduced to the fields this application uses."""

    osv_id: str
    summary: str | None
    severity: str | None
    published_at: datetime | None
    modified_at: datetime
    aliases: tuple[str, ...]
    affected_ranges: tuple[AffectedRangeData, ...]


def parse_osv_record(raw: dict[str, Any]) -> OsvRecord:
    published = raw.get("published")
    return OsvRecord(
        osv_id=raw["id"],
        summary=raw.get("summary"),
        severity=_severity(raw),
        published_at=datetime.fromisoformat(published) if published else None,
        modified_at=datetime.fromisoformat(raw["modified"]),
        aliases=tuple(raw.get("aliases", [])),
        affected_ranges=tuple(_affected_ranges(raw)),
    )


def _severity(raw: dict[str, Any]) -> str | None:
    level = raw.get("database_specific", {}).get("severity")
    if not isinstance(level, str):
        return None
    return _SEVERITY_LEVELS.get(level.upper())


def _affected_ranges(raw: dict[str, Any]) -> Iterator[AffectedRangeData]:
    for affected in raw.get("affected", []):
        package = affected.get("package", {})
        ecosystem, name = package.get("ecosystem"), package.get("name")
        if not ecosystem or not name:
            continue
        for version_range in affected.get("ranges", []):
            if version_range.get("type") not in _VERSION_RANGE_TYPES:
                continue
            for introduced, fixed, last_affected in _ranges_from_events(version_range["events"]):
                yield AffectedRangeData(ecosystem, name, introduced, fixed, last_affected)


def _ranges_from_events(
    events: list[dict[str, str]],
) -> Iterator[tuple[str, str | None, str | None]]:
    introduced: str | None = None
    for event in events:
        if "introduced" in event:
            if introduced is not None:
                yield introduced, None, None
            introduced = event["introduced"]
        elif introduced is not None and ("fixed" in event or "last_affected" in event):
            yield introduced, event.get("fixed"), event.get("last_affected")
            introduced = None
    if introduced is not None:
        yield introduced, None, None
