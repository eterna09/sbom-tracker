from datetime import timedelta

from sqlalchemy.orm import Session

from app.auth.tokens import create_access_token
from app.config import get_settings
from app.models import Membership, Organization, Role, User


def bearer_header(user_id: int) -> dict[str, str]:
    token = create_access_token(user_id, get_settings().jwt_secret_key, timedelta(minutes=5))
    return {"Authorization": f"Bearer {token}"}


def add_member(session: Session, organization: Organization, email: str, role: Role) -> User:
    user = User(email=email, password_hash="not-used-in-these-tests")
    session.add(Membership(user=user, organization=organization, role=role))
    session.flush()
    return user
