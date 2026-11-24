from app.models import Finding, FindingStatus, User

_ALLOWED_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.NEW: frozenset({FindingStatus.INVESTIGATING}),
    FindingStatus.INVESTIGATING: frozenset({FindingStatus.AFFECTED, FindingStatus.NOT_AFFECTED}),
    FindingStatus.AFFECTED: frozenset({FindingStatus.FIXED, FindingStatus.INVESTIGATING}),
    FindingStatus.NOT_AFFECTED: frozenset({FindingStatus.INVESTIGATING}),
    FindingStatus.FIXED: frozenset({FindingStatus.INVESTIGATING}),
}


def can_transition(current: FindingStatus, target: FindingStatus) -> bool:
    """Return True if a finding may move from `current` to `target`.

    Every verdict passes through `investigating`; reopening a decided finding
    returns it to `investigating`, never to `new`.
    """
    return target in _ALLOWED_TRANSITIONS[current]


class InvalidTransitionError(Exception):
    def __init__(self, current: FindingStatus, target: FindingStatus) -> None:
        super().__init__(f"Cannot move a finding from {current} to {target}")


def triage(finding: Finding, target: FindingStatus, justification: str | None, user: User) -> None:
    """Move `finding` to `target`, recording who decided and why."""
    if not can_transition(finding.status, target):
        raise InvalidTransitionError(finding.status, target)
    finding.status = target
    finding.justification = justification
    finding.triaged_by_id = user.id
