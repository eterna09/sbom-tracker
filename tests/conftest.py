from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

import app.models  # noqa: F401  registers all models on Base.metadata
from app.auth.rate_limit import reset_login_attempts
from app.cache import get_cache
from app.db import Base, get_session
from app.main import app
from app.models import Organization, Role, User
from tests.fakes import InMemoryCache
from tests.helpers import add_member


class TestSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    test_database_url: str


@pytest.fixture(scope="session")
def engine():
    engine = create_engine(TestSettings().test_database_url)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def session(engine) -> Iterator[Session]:
    connection = engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection, join_transaction_mode="create_savepoint")()
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def cache() -> InMemoryCache:
    return InMemoryCache()


@pytest.fixture
def client(session: Session) -> Iterator[TestClient]:
    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_cache] = lambda: cache
    yield TestClient(app)
    app.dependency_overrides.clear()
    cache: InMemoryCache


@pytest.fixture
def acme(session: Session) -> Organization:
    organization = Organization(name="Acme Machines")
    session.add(organization)
    session.flush()
    return organization


@pytest.fixture
def admin(session: Session, acme: Organization) -> User:
    return add_member(session, acme, "admin@acme.example", Role.ADMIN)


@pytest.fixture
def viewer(session: Session, acme: Organization) -> User:
    return add_member(session, acme, "viewer@acme.example", Role.VIEWER)


@pytest.fixture
def outsider(session: Session) -> User:
    globex = Organization(name="Globex")
    session.add(globex)
    session.flush()
    return add_member(session, globex, "admin@globex.example", Role.ADMIN)


@pytest.fixture(autouse=True)
def reset_rate_limits() -> Iterator[None]:
    reset_login_attempts()
    yield
