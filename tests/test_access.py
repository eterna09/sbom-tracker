import pytest

from app.auth.access import role_satisfies
from app.models import Role


@pytest.mark.parametrize(
    ("role", "minimum", "allowed"),
    [
        (Role.VIEWER, Role.VIEWER, True),
        (Role.VIEWER, Role.ANALYST, False),
        (Role.VIEWER, Role.ADMIN, False),
        (Role.ANALYST, Role.VIEWER, True),
        (Role.ANALYST, Role.ANALYST, True),
        (Role.ANALYST, Role.ADMIN, False),
        (Role.ADMIN, Role.VIEWER, True),
        (Role.ADMIN, Role.ANALYST, True),
        (Role.ADMIN, Role.ADMIN, True),
    ],
)
def test_role_satisfies_the_role_ladder(role: Role, minimum: Role, allowed: bool) -> None:
    assert role_satisfies(role, minimum) is allowed
