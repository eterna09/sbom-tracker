from collections.abc import Callable
from dataclasses import dataclass

import semver
from packaging.version import InvalidVersion, Version

VersionParser = Callable[[str], Version | semver.Version | None]


@dataclass(frozen=True)
class VersionRange:
    introduced: str | None
    fixed: str | None
    last_affected: str | None


def is_affected(ecosystem: str, version: str, version_range: VersionRange) -> bool:
    parse = _PARSERS.get(ecosystem)
    if parse is None:
        return False
    current = parse(version)
    return current is not None and _is_within(current, version_range, parse)


def _is_within(
    current: Version | semver.Version,
    version_range: VersionRange,
    parse: VersionParser,
) -> bool:
    if version_range.introduced not in (None, "0"):
        introduced = parse(version_range.introduced)
        if introduced is None or current < introduced:
            return False
    if version_range.fixed is not None:
        fixed = parse(version_range.fixed)
        return fixed is not None and current < fixed
    if version_range.last_affected is not None:
        last_affected = parse(version_range.last_affected)
        return last_affected is not None and current <= last_affected
    return True


def _parse_pypi(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _parse_npm(text: str) -> semver.Version | None:
    try:
        return semver.Version.parse(text)
    except ValueError:
        return None


_PARSERS: dict[str, VersionParser] = {
    "PyPI": _parse_pypi,
    "npm": _parse_npm,
}
