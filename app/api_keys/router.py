from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.audit.service import AuditAction, record
from app.auth.access import AdminAccess
from app.auth.api_keys import generate_api_key, hash_api_key
from app.db import SessionDep
from app.models import ApiKey

router = APIRouter(prefix="/organizations/{organization_id}/api-keys", tags=["api keys"])


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class ApiKeyOut(BaseModel):
    id: int
    name: str
    created_at: datetime
    revoked_at: datetime | None


class ApiKeyCreated(ApiKeyOut):
    key: str = Field(description="The full key. Shown only once; store it securely.")


def _to_out(api_key: ApiKey) -> ApiKeyOut:
    return ApiKeyOut(
        id=api_key.id,
        name=api_key.name,
        created_at=api_key.created_at,
        revoked_at=api_key.revoked_at,
    )


@router.post("", status_code=status.HTTP_201_CREATED, summary="Create an API key (shown once)")
def create_api_key(
    payload: ApiKeyCreate, access: AdminAccess, session: SessionDep
) -> ApiKeyCreated:
    plaintext = generate_api_key()
    api_key = ApiKey(
        organization_id=access.organization.id,
        name=payload.name,
        key_hash=hash_api_key(plaintext),
    )
    session.add(api_key)
    session.flush()
    record(
        session,
        AuditAction.API_KEY_CREATED,
        organization_id=access.organization.id,
        user_id=access.user.id,
        api_key_id=api_key.id,
        target_type="api_key",
        target_id=api_key.id,
        details={"name": api_key.name},
    )
    session.commit()
    return ApiKeyCreated(**_to_out(api_key).model_dump(), key=plaintext)


@router.get("", summary="List the organisation's API keys")
def list_api_keys(access: AdminAccess, session: SessionDep) -> list[ApiKeyOut]:
    api_keys = session.scalars(
        select(ApiKey).where(ApiKey.organization_id == access.organization.id).order_by(ApiKey.id)
    )
    return [_to_out(api_key) for api_key in api_keys]


@router.post("/{api_key_id}/revoke", summary="Revoke an API key")
def revoke_api_key(api_key_id: int, access: AdminAccess, session: SessionDep) -> ApiKeyOut:
    api_key = session.scalar(
        select(ApiKey).where(
            ApiKey.id == api_key_id, ApiKey.organization_id == access.organization.id
        )
    )
    if api_key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    if api_key.revoked_at is None:
        api_key.revoked_at = datetime.now(UTC)
        record(
            session,
            AuditAction.API_KEY_REVOKED,
            organization_id=access.organization.id,
            user_id=access.user.id,
            api_key_id=api_key.id,
            target_type="api_key",
            target_id=api_key.id,
        )
        session.commit()
    return _to_out(api_key)
