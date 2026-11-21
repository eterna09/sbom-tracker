"""Mark vulnerabilities listed in the CISA KEV catalogue as known exploited.

Run with: python -m app.vulnerabilities.mark_kev data/kev.json
"""

import json
import sys
from pathlib import Path

from app.db import open_session
from app.vulnerabilities.kev import mark_known_exploited, parse_kev_catalog


def main(argv: list[str]) -> None:
    if len(argv) != 2:
        sys.exit("Usage: python -m app.vulnerabilities.mark_kev <kev-catalogue.json>")
    catalog = parse_kev_catalog(json.loads(Path(argv[1]).read_text(encoding="utf-8")))
    with open_session() as session, session.begin():
        result = mark_known_exploited(session, catalog)
    print(f"KEV entries: {len(catalog)}, marked: {result.marked}, unmarked: {result.unmarked}")


if __name__ == "__main__":
    main(sys.argv)
