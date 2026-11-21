import enum
import json
import zipfile
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path

from sqlalchemy import select
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
    return Counter(import_record(session, record) for record in records)


def import_record(session: Session, record: OsvRecord) -> ImportOutcome:
    """Insert a new vulnerability, update a changed one, or skip an unchanged one."""
    vulnerability = session.scalar(
        select(Vulnerability).where(Vulnerability.osv_id == record.osv_id)
    )
    if vulnerability is None:
        vulnerability = Vulnerability(osv_id=record.osv_id)
        session.add(vulnerability)
        outcome = ImportOutcome.CREATED
    elif vulnerability.modified_at == record.modified_at:
        return ImportOutcome.UNCHANGED
    else:
        _remove_details(session, vulnerability)
        outcome = ImportOutcome.UPDATED
    _apply_record(vulnerability, record)
    return outcome


def _remove_details(session: Session, vulnerability: Vulnerability) -> None:
    vulnerability.aliases.clear()
    vulnerability.affected_ranges.clear()
    session.flush()


def _apply_record(vulnerability: Vulnerability, record: OsvRecord) -> None:
    vulnerability.summary = record.summary
    vulnerability.severity = record.severity
    vulnerability.published_at = record.published_at
    vulnerability.modified_at = record.modified_at
    vulnerability.aliases = [
        VulnerabilityAlias(alias=alias) for alias in dict.fromkeys(record.aliases)
    ]
    vulnerability.affected_ranges = [
        AffectedRange(
            ecosystem=data.ecosystem,
            package_name=data.package_name,
            introduced=data.introduced,
            fixed=data.fixed,
            last_affected=data.last_affected,
        )
        for data in record.affected_ranges
    ]
