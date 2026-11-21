from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import open_session
from app.matching.service import match_product_version
from app.models import ProductVersion


def rematch_all(session: Session) -> tuple[int, int]:
    """Re-match every version with an SBOM; return (versions matched, new findings)."""
    versions = session.scalars(
        select(ProductVersion).where(ProductVersion.sbom_uploaded_at.is_not(None))
    ).all()
    created = sum(match_product_version(session, version) for version in versions)
    return len(versions), created


def main() -> None:
    with open_session() as session, session.begin():
        versions, created = rematch_all(session)
    print(f"Re-matched {versions} product versions: {created} new findings")


if __name__ == "__main__":
    main()
