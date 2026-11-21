from datetime import UTC, datetime

import pytest

from app.vulnerabilities.osv import AffectedRangeData, parse_osv_record
from tests.helpers import osv_record


def ranges(*events: dict, range_type: str = "ECOSYSTEM") -> list[dict]:
    return [
        {
            "package": {"ecosystem": "PyPI", "name": "demo"},
            "ranges": [{"type": range_type, "events": list(events)}],
        }
    ]


def test_parses_identity_aliases_and_timestamps() -> None:
    record = parse_osv_record(osv_record())

    assert record.osv_id == "GHSA-h5c8-rqwp-cp95"
    assert record.aliases == ("CVE-2024-22195",)
    assert record.summary.startswith("Jinja vulnerable")
    assert record.published_at == datetime(2024, 1, 11, 15, 20, 48, tzinfo=UTC)
    assert record.modified_at == datetime(2024, 5, 6, 14, 46, 41, tzinfo=UTC)


@pytest.mark.parametrize(
    ("osv_severity", "expected"),
    [("CRITICAL", "critical"), ("HIGH", "high"), ("MODERATE", "medium"), ("LOW", "low")],
)
def test_severity_is_normalised(osv_severity: str, expected: str) -> None:
    record = parse_osv_record(osv_record(database_specific={"severity": osv_severity}))

    assert record.severity == expected


def test_missing_severity_and_summary_become_none() -> None:
    raw = osv_record()
    del raw["database_specific"]
    del raw["summary"]

    record = parse_osv_record(raw)

    assert record.severity is None
    assert record.summary is None


def test_introduced_and_fixed_form_one_range() -> None:
    record = parse_osv_record(osv_record())

    assert record.affected_ranges == (
        AffectedRangeData("PyPI", "jinja2", introduced="0", fixed="3.1.3", last_affected=None),
    )


def test_several_introduced_fixed_pairs_form_several_ranges() -> None:
    raw = osv_record(
        affected=ranges(
            {"introduced": "0"}, {"fixed": "1.0"}, {"introduced": "2.0"}, {"fixed": "2.1"}
        )
    )

    record = parse_osv_record(raw)

    assert [(r.introduced, r.fixed) for r in record.affected_ranges] == [
        ("0", "1.0"),
        ("2.0", "2.1"),
    ]


def test_last_affected_closes_a_range() -> None:
    raw = osv_record(affected=ranges({"introduced": "1.0"}, {"last_affected": "1.4"}))

    record = parse_osv_record(raw)

    assert record.affected_ranges[0].last_affected == "1.4"
    assert record.affected_ranges[0].fixed is None


def test_range_without_fix_stays_open() -> None:
    raw = osv_record(affected=ranges({"introduced": "1.0"}))

    record = parse_osv_record(raw)

    assert record.affected_ranges == (
        AffectedRangeData("PyPI", "demo", introduced="1.0", fixed=None, last_affected=None),
    )


def test_git_commit_ranges_are_ignored() -> None:
    raw = osv_record(
        affected=ranges({"introduced": "abc123"}, {"fixed": "def456"}, range_type="GIT")
    )

    record = parse_osv_record(raw)

    assert record.affected_ranges == ()


def test_pypi_package_names_are_stored_normalised() -> None:
    record = parse_osv_record(
        osv_record(
            affected=[
                {
                    "package": {"ecosystem": "PyPI", "name": "Jinja2"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.11.3"}],
                        }
                    ],
                }
            ]
        )
    )

    assert record.affected_ranges[0].package_name == "jinja2"
