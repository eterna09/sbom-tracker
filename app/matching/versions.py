from dataclasses import dataclass

import semver
from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class VersionRange:
    introduced: str | None
    fixed: str | None
    last_affected: str | None


def is_affected(ecosystem: str, version: str, version_range: VersionRange) -> bool:
    if ecosystem == "PyPI":
        current = _parse_pypi(version)
        if current is None:
            return False
        if version_range.introduced not in (None, "0"):
            introduced = _parse_pypi(version_range.introduced)
            if introduced is None or current < introduced:
                return False
        if version_range.fixed is not None:
            fixed = _parse_pypi(version_range.fixed)
            return fixed is not None and current < fixed
        if version_range.last_affected is not None:
            last_affected = _parse_pypi(version_range.last_affected)
            return last_affected is not None and current <= last_affected
        return True
    if ecosystem == "npm":
        current = _parse_npm(version)
        if current is None:
            return False
        if version_range.introduced not in (None, "0"):
            introduced = _parse_npm(version_range.introduced)
            if introduced is None or current < introduced:
                return False
        if version_range.fixed is not None:
            fixed = _parse_npm(version_range.fixed)
            return fixed is not None and current < fixed
        if version_range.last_affected is not None:
            last_affected = _parse_npm(version_range.last_affected)
            return last_affected is not None and current <= last_affected
        return True
    return False


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
