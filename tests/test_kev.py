from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Vulnerability
from app.vulnerabilities.importer import import_record
from app.vulnerabilities.kev import mark_known_exploited, parse_kev_catalog
from app.vulnerabilities.osv import parse_osv_record
from tests.helpers import osv_record


def add_vulnerability(session: Session, osv_id: str, *aliases: str) -> None:
    import_record(session, parse_osv_record(osv_record(id=osv_id, aliases=list(aliases))))
    session.flush()


def vulnerability(session: Session, osv_id: str) -> Vulnerability:
    session.expire_all()
    found = session.scalar(select(Vulnerability).where(Vulnerability.osv_id == osv_id))
    assert found is not None
    return found


def test_catalog_is_parsed_into_cve_dates() -> None:
    catalog = {
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"},
            {"cveID": "CVE-2023-0001", "dateAdded": "2023-02-01"},
        ]
    }

    assert parse_kev_catalog(catalog) == {
        "CVE-2021-44228": date(2021, 12, 10),
        "CVE-2023-0001": date(2023, 2, 1),
    }


def test_vulnerability_with_listed_cve_alias_is_marked(session: Session) -> None:
    add_vulnerability(session, "GHSA-1", "CVE-2021-44228")

    result = mark_known_exploited(session, {"CVE-2021-44228": date(2021, 12, 10)})

    marked = vulnerability(session, "GHSA-1")
    assert marked.is_known_exploited is True
    assert marked.kev_added_at == datetime(2021, 12, 10, tzinfo=UTC)
    assert result.marked == 1


def test_vulnerability_without_listed_alias_stays_unmarked(session: Session) -> None:
    add_vulnerability(session, "GHSA-1", "CVE-2020-0001")

    mark_known_exploited(session, {"CVE-2021-44228": date(2021, 12, 10)})

    assert vulnerability(session, "GHSA-1").is_known_exploited is False


def test_every_record_sharing_the_cve_is_marked(session: Session) -> None:
    add_vulnerability(session, "GHSA-1", "CVE-2021-44228")
    add_vulnerability(session, "PYSEC-1", "CVE-2021-44228")

    result = mark_known_exploited(session, {"CVE-2021-44228": date(2021, 12, 10)})

    assert vulnerability(session, "GHSA-1").is_known_exploited is True
    assert vulnerability(session, "PYSEC-1").is_known_exploited is True
    assert result.marked == 2


def test_vulnerability_removed_from_the_list_is_unmarked(session: Session) -> None:
    add_vulnerability(session, "GHSA-1", "CVE-2021-44228")
    mark_known_exploited(session, {"CVE-2021-44228": date(2021, 12, 10)})

    result = mark_known_exploited(session, {})

    unmarked = vulnerability(session, "GHSA-1")
    assert unmarked.is_known_exploited is False
    assert unmarked.kev_added_at is None
    assert result.unmarked == 1
