from itertools import product

import pytest

from app.findings.triage import can_transition
from app.models import FindingStatus

NEW = FindingStatus.NEW
INVESTIGATING = FindingStatus.INVESTIGATING
AFFECTED = FindingStatus.AFFECTED
NOT_AFFECTED = FindingStatus.NOT_AFFECTED
FIXED = FindingStatus.FIXED

ALLOWED = {
    (NEW, INVESTIGATING),
    (INVESTIGATING, AFFECTED),
    (INVESTIGATING, NOT_AFFECTED),
    (AFFECTED, FIXED),
    (AFFECTED, INVESTIGATING),
    (NOT_AFFECTED, INVESTIGATING),
    (FIXED, INVESTIGATING),
}


@pytest.mark.parametrize(
    ("current", "target"),
    list(product(FindingStatus, repeat=2)),
    ids=lambda status: status.value,
)
def test_only_defined_transitions_are_allowed(
    current: FindingStatus, target: FindingStatus
) -> None:
    assert can_transition(current, target) is ((current, target) in ALLOWED)
