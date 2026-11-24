from datetime import timedelta

from sqlalchemy.orm import Session

from app.auth.tokens import create_access_token
from app.config import get_settings
from app.models import (
    Component,
    Finding,
    FindingStatus,
    Membership,
    Organization,
    Product,
    ProductVersion,
    Role,
    User,
    Vulnerability,
)


def bearer_header(user_id: int) -> dict[str, str]:
    token = create_access_token(user_id, get_settings().jwt_secret_key, timedelta(minutes=5))
    return {"Authorization": f"Bearer {token}"}


def add_member(session: Session, organization: Organization, email: str, role: Role) -> User:
    user = User(email=email, password_hash="not-used-in-these-tests")
    session.add(Membership(user=user, organization=organization, role=role))
    session.flush()
    return user


def osv_record(**overrides: object) -> dict:
    record = {
        "id": "GHSA-h5c8-rqwp-cp95",
        "modified": "2024-05-06T14:46:41Z",
        "published": "2024-01-11T15:20:48Z",
        "aliases": ["CVE-2024-22195"],
        "summary": "Jinja vulnerable to HTML attribute injection via the xmlattr filter",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "jinja2"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}
                ],
            }
        ],
        "database_specific": {"severity": "MODERATE"},
    }
    record.update(overrides)
    return record


def add_product_version(
    session: Session, organization: Organization, product_name: str = "Pump Controller"
) -> ProductVersion:
    product = Product(organization_id=organization.id, name=product_name)
    product_version = ProductVersion(product=product, version="1.0")
    session.add(product_version)
    session.flush()
    return product_version


def add_finding(
    session: Session,
    product_version: ProductVersion,
    osv_id: str,
    known_exploited: bool = False,
    status: FindingStatus = FindingStatus.NEW,
    severity: str = "high",
) -> Finding:
    component = Component(ecosystem="PyPI", name=f"pkg-{osv_id.lower()}", version="1.0.0")
    vulnerability = Vulnerability(
        osv_id=osv_id, severity="high", is_known_exploited=known_exploited
    )
    session.add_all([component, vulnerability])
    session.flush()
    finding = Finding(
        product_version_id=product_version.id,
        component_id=component.id,
        vulnerability_id=vulnerability.id,
        status=status,
    )
    session.add(finding)
    session.flush()
    return finding
