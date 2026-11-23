from app.models import FindingStatus

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
