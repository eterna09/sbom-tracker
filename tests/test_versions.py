import pytest

from app.matching.versions import VersionRange, is_affected

FROM_START_FIXED_IN_3_1_3 = VersionRange(introduced="0", fixed="3.1.3", last_affected=None)


@pytest.mark.parametrize(
    ("version", "version_range", "expected"),
    [
        ("2.10.1", FROM_START_FIXED_IN_3_1_3, True),
        ("3.1.3", FROM_START_FIXED_IN_3_1_3, False),
        ("3.2.0", FROM_START_FIXED_IN_3_1_3, False),
        ("1.9.0", VersionRange(introduced="1.10.0", fixed=None, last_affected=None), False),
        ("1.10.0", VersionRange(introduced="1.9.0", fixed="1.11.0", last_affected=None), True),
        ("1.0rc1", VersionRange(introduced="0", fixed="1.0", last_affected=None), True),
        ("1.4", VersionRange(introduced="1.0", fixed=None, last_affected="1.4"), True),
        ("1.5", VersionRange(introduced="1.0", fixed=None, last_affected="1.4"), False),
        ("2.0", VersionRange(introduced="1.0", fixed=None, last_affected=None), True),
        ("not-a-version", FROM_START_FIXED_IN_3_1_3, False),
    ],
)
def test_pypi_versions_follow_pep_440(
    version: str, version_range: VersionRange, expected: bool
) -> None:
    assert is_affected("PyPI", version, version_range) is expected


@pytest.mark.parametrize(
    ("version", "version_range", "expected"),
    [
        ("4.17.20", VersionRange(introduced="0", fixed="4.17.21", last_affected=None), True),
        ("4.17.21", VersionRange(introduced="0", fixed="4.17.21", last_affected=None), False),
        ("1.0.0-beta.2", VersionRange(introduced="0", fixed="1.0.0", last_affected=None), True),
        ("1.10.0", VersionRange(introduced="1.9.0", fixed=None, last_affected=None), True),
        ("1.2", VersionRange(introduced="0", fixed="2.0.0", last_affected=None), False),
    ],
)
def test_npm_versions_follow_semantic_versioning(
    version: str, version_range: VersionRange, expected: bool
) -> None:
    assert is_affected("npm", version, version_range) is expected


def test_unsupported_ecosystem_is_never_reported_as_affected() -> None:
    assert is_affected("Maven", "2.14.1", FROM_START_FIXED_IN_3_1_3) is False
