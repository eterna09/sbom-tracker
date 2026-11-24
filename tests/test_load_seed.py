import pytest

from loadtests.seed_load_data import ensure_local_database


def test_local_database_is_accepted() -> None:
    ensure_local_database("postgresql+psycopg://sbom:secret@localhost:5433/sbom_tracker")


def test_remote_database_is_refused() -> None:
    with pytest.raises(SystemExit):
        ensure_local_database(
            "postgresql+psycopg://user:secret@ep-example.eu-central-1.aws.neon.tech/neondb"
        )
