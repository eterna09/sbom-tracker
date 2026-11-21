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
        try:
            current = Version(version)
        except InvalidVersion:
            return False
        if version_range.introduced not in (None, "0"):
            try:
                if current < Version(version_range.introduced):
                    return False
            except InvalidVersion:
                return False
        if version_range.fixed is not None:
            try:
                return current < Version(version_range.fixed)
            except InvalidVersion:
                return False
        if version_range.last_affected is not None:
            try:
                return current <= Version(version_range.last_affected)
            except InvalidVersion:
                return False
        return True
    if ecosystem == "npm":
        try:
            current = semver.Version.parse(version)
        except ValueError:
            return False
        if version_range.introduced not in (None, "0"):
            try:
                if current < semver.Version.parse(version_range.introduced):
                    return False
            except ValueError:
                return False
        if version_range.fixed is not None:
            try:
                return current < semver.Version.parse(version_range.fixed)
            except ValueError:
                return False
        if version_range.last_affected is not None:
            try:
                return current <= semver.Version.parse(version_range.last_affected)
            except ValueError:
                return False
        return True
    return False
