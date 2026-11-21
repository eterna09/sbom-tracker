import pytest

from app.sboms.purls import ComponentRef, parse_purl


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:pypi/jinja2@2.10.1", ComponentRef("PyPI", "jinja2", "2.10.1")),
        ("pkg:npm/%40angular/core@16.0.0", ComponentRef("npm", "@angular/core", "16.0.0")),
        ("pkg:npm/lodash@4.17.20", ComponentRef("npm", "lodash", "4.17.20")),
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            ComponentRef("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
        ),
    ],
)
def test_supported_purls_become_component_refs(purl: str, expected: ComponentRef) -> None:
    assert parse_purl(purl) == expected


@pytest.mark.parametrize(
    "purl",
    [
        "not-a-purl",
        "pkg:pypi/requests",
        "pkg:deb/debian/openssl@3.0.11",
    ],
)
def test_unusable_purls_are_ignored(purl: str) -> None:
    assert parse_purl(purl) is None
