from collections.abc import Callable
from dataclasses import dataclass

import semver
from packaging.version import InvalidVersion, Version

VersionParser = Callable[[str], Version | semver.Version | None]
# OSV uses "0" as the introduced version for "affected since the first release".
_FROM_THE_START = "0"


@dataclass(frozen=True)
class VersionRange:
    introduced: str | None
    fixed: str | None
    last_affected: str | None


def is_affected(ecosystem: str, version: str, version_range: VersionRange) -> bool:
    """Return True if `version` lies in `version_range` under the ecosystem's rules.

    Unparsable versions and unsupported ecosystems count as not affected:
    a deliberate trade-off that avoids false alarms but can miss malformed data.
    """
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
    if version_range.introduced not in (None, _FROM_THE_START):
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
