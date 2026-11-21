from collections import defaultdict

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from app.matching.names import normalize_package_name
from app.matching.versions import VersionRange, is_affected
from app.models import AffectedRange, Component, Finding, ProductVersion

PackageKey = tuple[str, str]
FindingKey = tuple[int, int]


def match_product_version(session: Session, product_version: ProductVersion) -> int:
    """Create a finding for each vulnerability that affects a component of the version.

    Existing findings are left untouched, so triage decisions survive re-matching.
    Returns the number of new findings. The caller commits.
    """
    components = _components_by_package(product_version.components)
    if not components:
        return 0
    new_keys = _affected_keys(session, components) - _existing_keys(session, product_version.id)
    session.add_all(
        Finding(
            product_version_id=product_version.id,
            component_id=component_id,
            vulnerability_id=vulnerability_id,
        )
        for component_id, vulnerability_id in new_keys
    )
    session.flush()
    return len(new_keys)


def _components_by_package(components: list[Component]) -> dict[PackageKey, list[Component]]:
    grouped: dict[PackageKey, list[Component]] = defaultdict(list)
    for component in components:
        name = normalize_package_name(component.ecosystem, component.name)
        grouped[(component.ecosystem, name)].append(component)
    return grouped


def _affected_keys(
    session: Session, components: dict[PackageKey, list[Component]]
) -> set[FindingKey]:
    ranges = session.scalars(
        select(AffectedRange).where(
            tuple_(AffectedRange.ecosystem, AffectedRange.package_name).in_(list(components))
        )
    )
    keys: set[FindingKey] = set()
    for affected_range in ranges:
        version_range = VersionRange(
            affected_range.introduced, affected_range.fixed, affected_range.last_affected
        )
        for component in components[(affected_range.ecosystem, affected_range.package_name)]:
            if is_affected(component.ecosystem, component.version, version_range):
                keys.add((component.id, affected_range.vulnerability_id))
    return keys


def _existing_keys(session: Session, product_version_id: int) -> set[FindingKey]:
    rows = session.execute(
        select(Finding.component_id, Finding.vulnerability_id).where(
            Finding.product_version_id == product_version_id
        )
    )
    return {(component_id, vulnerability_id) for component_id, vulnerability_id in rows}
