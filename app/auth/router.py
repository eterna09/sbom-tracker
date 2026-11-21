from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser
from app.auth.service import authenticate_user
from app.auth.tokens import create_access_token
from app.config import Settings, get_settings
from app.db import get_session
from app.models import Role

router = APIRouter(prefix="/auth", tags=["auth"])


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105  OAuth2 token type name, not a secret


class MembershipOut(BaseModel):
    organization_id: int
    organization_name: str
    role: Role


class MeResponse(BaseModel):
    id: int
    email: str
    memberships: list[MembershipOut]


@router.post("/token", summary="Log in and receive an access token")
def login(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenResponse:
    user = authenticate_user(session, form.username, form.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    lifetime = timedelta(minutes=settings.access_token_lifetime_minutes)
    return TokenResponse(
        access_token=create_access_token(user.id, settings.jwt_secret_key, lifetime)
    )


@router.get("/me", summary="Show the logged-in user and their organisations")
def read_me(user: CurrentUser) -> MeResponse:
    return MeResponse(
        id=user.id,
        email=user.email,
        memberships=[
            MembershipOut(
                organization_id=membership.organization_id,
                organization_name=membership.organization.name,
                role=membership.role,
            )
            for membership in user.memberships
        ],
    )
