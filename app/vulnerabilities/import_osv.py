"""Import an OSV ecosystem export (zip) into the database.

Run with: python -m app.vulnerabilities.import_osv data/osv-pypi.zip
"""

import sys
from collections import Counter
from itertools import batched
from pathlib import Path

from app.db import open_session
from app.vulnerabilities.importer import ImportOutcome, import_records, read_osv_zip

BATCH_SIZE = 500


def main(argv: list[str]) -> None:
    if len(argv) != 2:
        sys.exit("Usage: python -m app.vulnerabilities.import_osv <osv-export.zip>")
    totals: Counter[ImportOutcome] = Counter()
    for batch in batched(read_osv_zip(Path(argv[1])), BATCH_SIZE):
        with open_session() as session, session.begin():
            totals += import_records(session, batch)
        print(f"processed {sum(totals.values())} records — {_describe(totals)}")


def _describe(totals: Counter[ImportOutcome]) -> str:
    return ", ".join(f"{outcome}: {totals[outcome]}" for outcome in ImportOutcome)


if __name__ == "__main__":
    main(sys.argv)
