import pytest

from app.matching.names import normalize_package_name


@pytest.mark.parametrize(
    ("ecosystem", "name", "expected"),
    [
        ("PyPI", "Jinja2", "jinja2"),
        ("PyPI", "ruamel_yaml", "ruamel-yaml"),
        ("PyPI", "zope.interface", "zope-interface"),
        ("PyPI", "Foo__Bar.-baz", "foo-bar-baz"),
        ("npm", "lodash", "lodash"),
        ("Maven", "org.Apache.logging:log4j-core", "org.Apache.logging:log4j-core"),
    ],
)
def test_package_names_are_normalised_per_ecosystem(
    ecosystem: str, name: str, expected: str
) -> None:
    assert normalize_package_name(ecosystem, name) == expected
