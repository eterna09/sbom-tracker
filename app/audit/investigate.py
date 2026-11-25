"""List failed login attempts against one account.

Run with: python -m app.audit.investigate admin@acme.example
"""

import sys

from app.audit.queries import failed_logins_for
from app.db import open_session


def main(argv: list[str]) -> None:
    if len(argv) != 2:
        sys.exit("Usage: python -m app.audit.investigate <email>")
    with open_session() as session:
        entries = failed_logins_for(session, argv[1])
        for entry in entries:
            print(entry.occurred_at.isoformat())
    print(f"{len(entries)} failed login attempts (newest first, at most 100)")


if __name__ == "__main__":
    main(sys.argv)
