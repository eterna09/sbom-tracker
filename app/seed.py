"""demo organisation with one member per role.

Run with: python -m app.seed
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.passwords import hash_password
from app.db import open_session
from app.models import Membership, Organization, Role, User

DEMO_ORGANIZATION_NAME = "Acme Machines"
DEMO_MEMBERS = {
    "admin@acme.example": Role.ADMIN,
    "analyst@acme.example": Role.ANALYST,
    "viewer@acme.example": Role.VIEWER,
}


class SeedSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    demo_password: str


def get_or_create_organization(session: Session, name: str) -> Organization:
    organization = session.scalar(select(Organization).where(Organization.name == name))
    if organization is None:
        organization = Organization(name=name)
        session.add(organization)
        session.flush()
    return organization


def get_or_create_user(session: Session, email: str, password: str) -> User:
    user = session.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(email=email, password_hash=hash_password(password))
        session.add(user)
        session.flush()
    return user


def ensure_membership(session: Session, user: User, organization: Organization, role: Role) -> None:
    membership = session.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.organization_id == organization.id,
        )
    )
    if membership is None:
        session.add(Membership(user=user, organization=organization, role=role))


def seed_demo_data(session: Session, password: str) -> None:
    organization = get_or_create_organization(session, DEMO_ORGANIZATION_NAME)
    for email, role in DEMO_MEMBERS.items():
        user = get_or_create_user(session, email, password)
        ensure_membership(session, user, organization, role)


def main() -> None:
    password = SeedSettings().demo_password
    with open_session() as session, session.begin():
        seed_demo_data(session, password)
    print(f"Seeded '{DEMO_ORGANIZATION_NAME}' with {len(DEMO_MEMBERS)} members.")


if __name__ == "__main__":
    main()
