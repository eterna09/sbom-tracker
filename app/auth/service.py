from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.passwords import hash_password, verify_password
from app.models import User

_TIMING_EQUALISER_HASH = hash_password("timing-equaliser")


def authenticate_user(session: Session, email: str, password: str) -> User | None:
    user = session.scalar(select(User).where(User.email == email))
    if user is None:
        verify_password(password, _TIMING_EQUALISER_HASH)
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user
