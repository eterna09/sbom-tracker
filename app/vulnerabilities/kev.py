from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import Vulnerability, VulnerabilityAlias


@dataclass(frozen=True)
class MarkingResult:
    marked: int
    unmarked: int


def parse_kev_catalog(raw: dict[str, Any]) -> dict[str, date]:
    """Map each CVE id in a CISA KEV catalogue to the date it was added."""
    return {
        entry["cveID"]: date.fromisoformat(entry["dateAdded"])
        for entry in raw.get("vulnerabilities", [])
    }


def mark_known_exploited(session: Session, added_by_cve: Mapping[str, date]) -> MarkingResult:
    """Make `is_known_exploited` mirror the given list exactly: mark listed, unmark the rest."""
    added_by_vulnerability = _find_listed_vulnerabilities(session, added_by_cve)
    unmarked = _unmark_all_except(session, added_by_vulnerability.keys())
    _mark(session, added_by_vulnerability)
    return MarkingResult(marked=len(added_by_vulnerability), unmarked=unmarked)


def _find_listed_vulnerabilities(
    session: Session, added_by_cve: Mapping[str, date]
) -> dict[int, datetime]:
    if not added_by_cve:
        return {}
    rows = session.execute(
        select(VulnerabilityAlias.vulnerability_id, VulnerabilityAlias.alias).where(
            VulnerabilityAlias.alias.in_(added_by_cve.keys())
        )
    )
    added_by_vulnerability: dict[int, datetime] = {}
    for vulnerability_id, alias in rows:
        added_at = datetime.combine(added_by_cve[alias], time(), tzinfo=UTC)
        earliest = added_by_vulnerability.get(vulnerability_id, added_at)
        added_by_vulnerability[vulnerability_id] = min(earliest, added_at)
    return added_by_vulnerability


def _unmark_all_except(session: Session, keep_ids: Iterable[int]) -> int:
    result = session.execute(
        update(Vulnerability)
        .where(Vulnerability.is_known_exploited.is_(True), Vulnerability.id.not_in(keep_ids))
        .values(is_known_exploited=False, kev_added_at=None)
    )
    return result.rowcount


def _mark(session: Session, added_by_vulnerability: dict[int, datetime]) -> None:
    if not added_by_vulnerability:
        return
    session.execute(
        update(Vulnerability),
        [
            {"id": vulnerability_id, "is_known_exploited": True, "kev_added_at": added_at}
            for vulnerability_id, added_at in added_by_vulnerability.items()
        ],
    )
