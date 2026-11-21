import json
import zipfile
from collections import Counter
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Vulnerability, VulnerabilityAlias
from app.vulnerabilities.importer import (
    ImportOutcome,
    import_record,
    import_records,
    read_osv_zip,
)
from app.vulnerabilities.osv import parse_osv_record
from tests.helpers import osv_record


def stored_vulnerability(session: Session) -> Vulnerability:
    session.flush()
    session.expire_all()
    vulnerability = session.scalar(select(Vulnerability))
    assert vulnerability is not None
    return vulnerability


def test_new_record_is_created_with_aliases_and_ranges(session: Session) -> None:
    outcome = import_record(session, parse_osv_record(osv_record()))

    vulnerability = stored_vulnerability(session)
    assert outcome is ImportOutcome.CREATED
    assert vulnerability.osv_id == "GHSA-h5c8-rqwp-cp95"
    assert vulnerability.severity == "medium"
    assert [alias.alias for alias in vulnerability.aliases] == ["CVE-2024-22195"]
    assert [(r.package_name, r.introduced, r.fixed) for r in vulnerability.affected_ranges] == [
        ("jinja2", "0", "3.1.3")
    ]


def test_unchanged_record_is_skipped(session: Session) -> None:
    record = parse_osv_record(osv_record())
    import_record(session, record)
    session.flush()

    outcome = import_record(session, record)

    assert outcome is ImportOutcome.UNCHANGED
    assert session.scalar(select(func.count()).select_from(Vulnerability)) == 1


def test_newer_record_replaces_details_aliases_and_ranges(session: Session) -> None:
    import_record(session, parse_osv_record(osv_record()))
    session.flush()
    newer = osv_record(
        modified="2025-01-01T00:00:00Z",
        summary="Updated summary",
        aliases=["CVE-2024-22195", "PYSEC-2024-1"],
    )

    outcome = import_record(session, parse_osv_record(newer))

    vulnerability = stored_vulnerability(session)
    assert outcome is ImportOutcome.UPDATED
    assert vulnerability.summary == "Updated summary"
    assert sorted(alias.alias for alias in vulnerability.aliases) == [
        "CVE-2024-22195",
        "PYSEC-2024-1",
    ]
    assert session.scalar(select(func.count()).select_from(VulnerabilityAlias)) == 2


def test_records_are_read_from_an_osv_zip_export(session: Session, tmp_path: Path) -> None:
    export = tmp_path / "osv.zip"
    with zipfile.ZipFile(export, "w") as archive:
        archive.writestr("GHSA-1.json", json.dumps(osv_record(id="GHSA-1")))
        archive.writestr("GHSA-2.json", json.dumps(osv_record(id="GHSA-2")))

    outcomes = import_records(session, read_osv_zip(export))

    assert outcomes == Counter({ImportOutcome.CREATED: 2})
