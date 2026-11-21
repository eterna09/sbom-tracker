from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Component, ProductVersion
from app.sboms.purls import ComponentRef, parse_purl
from app.sboms.schemas import CycloneDxBom


@dataclass(frozen=True)
class UploadResult:
    components_stored: int
    components_skipped: int


def store_sbom(session: Session, version: ProductVersion, bom: CycloneDxBom) -> UploadResult:
    """Replace the version's component list with the components listed in the SBOM."""
    refs, skipped = _collect_component_refs(bom)
    version.components = [_get_or_create_component(session, ref) for ref in refs]
    version.sbom_uploaded_at = datetime.now(UTC)
    return UploadResult(components_stored=len(refs), components_skipped=skipped)


def _collect_component_refs(bom: CycloneDxBom) -> tuple[set[ComponentRef], int]:
    refs: set[ComponentRef] = set()
    skipped = 0
    for component in bom.components:
        ref = parse_purl(component.purl) if component.purl else None
        if ref is None:
            skipped += 1
        else:
            refs.add(ref)
    return refs, skipped


def _get_or_create_component(session: Session, ref: ComponentRef) -> Component:
    component = session.scalar(
        select(Component).where(
            Component.ecosystem == ref.ecosystem,
            Component.name == ref.name,
            Component.version == ref.version,
        )
    )
    if component is None:
        component = Component(ecosystem=ref.ecosystem, name=ref.name, version=ref.version)
        session.add(component)
    return component
