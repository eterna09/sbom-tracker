from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.passwords import verify_password
from app.models import Membership, Role, User
from app.seed import seed_demo_data


def test_seed_creates_one_member_per_role(session: Session) -> None:
    seed_demo_data(session, "demo-password")

    roles = set(session.scalars(select(Membership.role)))

    assert roles == {Role.ADMIN, Role.ANALYST, Role.VIEWER}


def test_seed_is_idempotent(session: Session) -> None:
    seed_demo_data(session, "demo-password")
    seed_demo_data(session, "demo-password")

    user_count = session.scalar(select(func.count()).select_from(User))

    assert user_count == 3


def test_seeded_passwords_are_stored_as_hashes(session: Session) -> None:
    seed_demo_data(session, "demo-password")

    admin = session.scalar(select(User).where(User.email == "admin@acme.example"))

    assert admin is not None
    assert admin.password_hash != "demo-password"
    assert verify_password("demo-password", admin.password_hash)
