import enum
import json
import zipfile
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path

from sqlalchemy import delete, insert, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.orm import Session

from app.models import AffectedRange, Vulnerability, VulnerabilityAlias
from app.vulnerabilities.osv import OsvRecord, parse_osv_record


class ImportOutcome(enum.StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    UNCHANGED = "unchanged"


def read_osv_zip(path: Path) -> Iterator[OsvRecord]:
    """Yield the records of an OSV export zip (one JSON file per vulnerability)."""
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if name.endswith(".json"):
                yield parse_osv_record(json.loads(archive.read(name)))


def import_records(session: Session, records: Iterable[OsvRecord]) -> Counter[ImportOutcome]:
    """Import a batch with a constant number of statements, whatever its size.

    One lookup, one upsert (INSERT ... ON CONFLICT), then the details in bulk.
    Known-exploited marks are never touched, because the upsert only sets OSV fields.
    """
    latest = _latest_per_osv_id(records)
    known = _known_modified_at(session, list(latest))
    outcomes: Counter[ImportOutcome] = Counter()
    to_write: list[OsvRecord] = []
    for osv_id, record in latest.items():
        if osv_id not in known:
            outcomes[ImportOutcome.CREATED] += 1
            to_write.append(record)
        elif known[osv_id] == record.modified_at:
            outcomes[ImportOutcome.UNCHANGED] += 1
        else:
            outcomes[ImportOutcome.UPDATED] += 1
            to_write.append(record)
    if to_write:
        vulnerability_ids = _upsert_vulnerabilities(session, to_write)
        _replace_details(session, vulnerability_ids, to_write)
    return outcomes


def import_record(session: Session, record: OsvRecord) -> ImportOutcome:
    """Import a single record (a batch of one)."""
    [outcome] = import_records(session, [record]).elements()
    return outcome


def _latest_per_osv_id(records: Iterable[OsvRecord]) -> dict[str, OsvRecord]:
    latest: dict[str, OsvRecord] = {}
    for record in records:
        current = latest.get(record.osv_id)
        if current is None or record.modified_at > current.modified_at:
            latest[record.osv_id] = record
    return latest


def _known_modified_at(session: Session, osv_ids: list[str]) -> dict[str, object]:
    rows = session.execute(
        select(Vulnerability.osv_id, Vulnerability.modified_at).where(
            Vulnerability.osv_id.in_(osv_ids)
        )
    )
    return {osv_id: modified_at for osv_id, modified_at in rows}


def _upsert_vulnerabilities(session: Session, records: list[OsvRecord]) -> dict[str, int]:
    statement = postgresql_insert(Vulnerability).values(
        [
            {
                "osv_id": record.osv_id,
                "summary": record.summary,
                "severity": record.severity,
                "published_at": record.published_at,
                "modified_at": record.modified_at,
            }
            for record in records
        ]
    )
    statement = statement.on_conflict_do_update(
        index_elements=[Vulnerability.osv_id],
        set_={
            "summary": statement.excluded.summary,
            "severity": statement.excluded.severity,
            "published_at": statement.excluded.published_at,
            "modified_at": statement.excluded.modified_at,
        },
    ).returning(Vulnerability.osv_id, Vulnerability.id)
    return {osv_id: vulnerability_id for osv_id, vulnerability_id in session.execute(statement)}


def _replace_details(
    session: Session, vulnerability_ids: dict[str, int], records: list[OsvRecord]
) -> None:
    ids = list(vulnerability_ids.values())
    session.execute(
        delete(VulnerabilityAlias)
        .where(VulnerabilityAlias.vulnerability_id.in_(ids))
        .execution_options(synchronize_session=False)
    )
    session.execute(
        delete(AffectedRange)
        .where(AffectedRange.vulnerability_id.in_(ids))
        .execution_options(synchronize_session=False)
    )
    aliases = [
        {"vulnerability_id": vulnerability_ids[record.osv_id], "alias": alias}
        for record in records
        for alias in dict.fromkeys(record.aliases)
    ]
    ranges = [
        {
            "vulnerability_id": vulnerability_ids[record.osv_id],
            "ecosystem": data.ecosystem,
            "package_name": data.package_name,
            "introduced": data.introduced,
            "fixed": data.fixed,
            "last_affected": data.last_affected,
        }
        for record in records
        for data in record.affected_ranges
    ]
    if aliases:
        session.execute(insert(VulnerabilityAlias), aliases)
    if ranges:
        session.execute(insert(AffectedRange), ranges)
