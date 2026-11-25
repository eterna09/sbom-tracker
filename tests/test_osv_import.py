import json
import zipfile
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import event, func, select
from sqlalchemy.orm import Session

from app.models import Vulnerability, VulnerabilityAlias
from app.vulnerabilities.importer import (
    ImportOutcome,
    import_record,
    import_records,
    read_osv_zip,
)
from app.vulnerabilities.osv import OsvRecord, parse_osv_record
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


@contextmanager
def counting_statements(session: Session) -> Iterator[list[str]]:
    connection = session.connection()
    statements: list[str] = []

    def record_statement(conn, cursor, statement, parameters, context, executemany) -> None:
        statements.append(statement)

    event.listen(connection, "before_cursor_execute", record_statement)
    try:
        yield statements
    finally:
        event.remove(connection, "before_cursor_execute", record_statement)


def _records(prefix: str, count: int) -> list[OsvRecord]:
    return [parse_osv_record(osv_record(id=f"{prefix}-{number}")) for number in range(count)]


def test_a_batch_needs_the_same_number_of_statements_whatever_its_size(
    session: Session,
) -> None:
    with counting_statements(session) as small_batch:
        import_records(session, _records("SMALL", 10))
    with counting_statements(session) as large_batch:
        import_records(session, _records("LARGE", 50))

    assert len(small_batch) == len(large_batch)


def test_a_batch_reports_created_updated_and_unchanged(session: Session) -> None:
    import_records(
        session,
        [parse_osv_record(osv_record(id="GHSA-KEEP")), parse_osv_record(osv_record(id="GHSA-OLD"))],
    )

    outcomes = import_records(
        session,
        [
            parse_osv_record(osv_record(id="GHSA-KEEP")),
            parse_osv_record(osv_record(id="GHSA-OLD", modified="2025-01-01T00:00:00Z")),
            parse_osv_record(osv_record(id="GHSA-NEW")),
        ],
    )

    assert outcomes == Counter(
        {ImportOutcome.UNCHANGED: 1, ImportOutcome.UPDATED: 1, ImportOutcome.CREATED: 1}
    )


def test_an_update_keeps_the_known_exploited_mark(session: Session) -> None:
    import_record(session, parse_osv_record(osv_record()))
    vulnerability = stored_vulnerability(session)
    vulnerability.is_known_exploited = True
    session.flush()

    import_record(session, parse_osv_record(osv_record(modified="2025-01-01T00:00:00Z")))

    assert stored_vulnerability(session).is_known_exploited is True


def test_the_newest_of_duplicate_records_in_one_batch_wins(session: Session) -> None:
    older = parse_osv_record(osv_record(summary="Older summary"))
    newer = parse_osv_record(osv_record(modified="2025-01-01T00:00:00Z", summary="Newer summary"))

    import_records(session, [newer, older])

    assert session.scalar(select(func.count()).select_from(Vulnerability)) == 1
    assert stored_vulnerability(session).summary == "Newer summary"
