from dataclasses import dataclass


@dataclass(frozen=True)
class PageRequest:
    limit: int
    offset: int
