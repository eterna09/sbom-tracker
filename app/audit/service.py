from enum import StrEnum
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog

MAX_LOGGED_EMAIL_LENGTH = 320


class AuditAction(StrEnum):
    LOGIN_SUCCEEDED = "login.succeeded"
    LOGIN_FAILED = "login.failed"
    SBOM_UPLOADED = "sbom.uploaded"
    FINDING_TRIAGED = "finding.triaged"
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"


def record(
    session: Session,
    action: AuditAction,
    *,
    organization_id: int | None = None,
    user_id: int | None = None,
    api_key_id: int | None = None,
    target_type: str | None = None,
    target_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Add an audit entry to the session; it is committed together with the action it records."""
    session.add(
        AuditLog(
            action=action.value,
            organization_id=organization_id,
            user_id=user_id,
            api_key_id=api_key_id,
            target_type=target_type,
            target_id=target_id,
            details=details,
        )
    )


def attempted_email(username: str) -> str:
    """Normalise a login name for the audit log, bounded so it cannot flood the log."""
    return username.lower()[:MAX_LOGGED_EMAIL_LENGTH]
