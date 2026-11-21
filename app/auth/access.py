from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser
from app.db import get_session
from app.models import Membership, Organization, Role, User

_ROLE_RANK = {Role.VIEWER: 1, Role.ANALYST: 2, Role.ADMIN: 3}


def role_satisfies(role: Role, minimum: Role) -> bool:
    return _ROLE_RANK[role] >= _ROLE_RANK[minimum]


@dataclass(frozen=True)
class Access:
    """The calling user, the organisation the request is about, and their role in it."""

    user: User
    organization: Organization
    role: Role


def get_current_access(
    organization_id: int,
    user: CurrentUser,
    session: Annotated[Session, Depends(get_session)],
) -> Access:
    membership = session.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.organization_id == organization_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return Access(user=user, organization=membership.organization, role=membership.role)


CurrentAccess = Annotated[Access, Depends(get_current_access)]


def require_role(minimum: Role) -> Callable[[Access], Access]:
    def check_role(access: CurrentAccess) -> Access:
        if not role_satisfies(access.role, minimum):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return access

    return check_role


AdminAccess = Annotated[Access, Depends(require_role(Role.ADMIN))]
