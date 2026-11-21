from dataclasses import dataclass

from packageurl import PackageURL

_SUPPORTED_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "maven": "Maven"}


@dataclass(frozen=True)
class ComponentRef:
    """A package identified the way vulnerability databases identify it."""

    ecosystem: str
    name: str
    version: str


def parse_purl(purl: str) -> ComponentRef | None:
    try:
        package = PackageURL.from_string(purl)
    except ValueError:
        return None
    ecosystem = _SUPPORTED_ECOSYSTEMS.get(package.type)
    if ecosystem is None or package.version is None:
        return None
    return ComponentRef(ecosystem=ecosystem, name=_ecosystem_name(package), version=package.version)


def _ecosystem_name(package: PackageURL) -> str:
    if package.namespace is None:
        return package.name
    separator = ":" if package.type == "maven" else "/"
    return f"{package.namespace}{separator}{package.name}"
