# Implemented Security Measures

This list contains only measures that are **implemented and merged**. Planned measures are listed in the [threat model](threat-model.md).

## Authentication

| Measure | Where |
|---|---|
| Passwords stored only as **Argon2id** hashes (argon2-cffi, library defaults per RFC 9106); random salt per hash | `app/auth/passwords.py` |
| Password verification fails safely: wrong passwords and malformed hashes both return `False`, never an exception | `app/auth/passwords.py`, `tests/test_passwords.py` |
| Login via the standard OAuth2 password flow; no custom authentication scheme | `app/auth/router.py` |
| **No user enumeration:** identical 401 message for unknown email and wrong password | `app/auth/router.py`, `tests/test_login.py` |
| **Timing-attack protection:** unknown emails still run a dummy Argon2 verification, so response times don't reveal which accounts exist | `app/auth/service.py` |

## Tokens

| Measure | Where |
|---|---|
| Signed JWT access tokens (HS256, PyJWT); no custom token format | `app/auth/tokens.py` |
| Accepted algorithm **pinned server-side**, which rejects `alg: none` and algorithm-confusion attacks | `app/auth/tokens.py`, `tests/test_tokens.py` |
| Required claims `sub`, `iat`, `exp`; tokens without expiry are rejected | `app/auth/tokens.py` |
| Short lifetime (30 minutes, configurable) | `app/config.py` |
| Forged, expired, unsigned and malformed tokens all raise one internal error, so no detail leaks about which check failed | `app/auth/tokens.py`, `tests/test_tokens.py` |
| Signing key generated with Python's `secrets` module (cryptographically secure), 64 bytes | deployment procedure |

## Secrets management

| Measure | Where |
|---|---|
| All secrets come from the environment; the app refuses to start if a required secret is missing (fail fast) | `app/config.py` |
| `.env` is git-ignored; `.env.example` contains placeholders only | `.gitignore`, `.env.example` |
| **Separate secrets per environment:** development (`.env`), CI (throwaway values), production (Render environment variables) | `.github/workflows/ci.yml`, Render settings |
| Demo user passwords come from the environment, never from code | `app/seed.py` |
| Secrets entered via hidden terminal input (`read -rs`), so they don't land in shell history | deployment procedure |
| **Credential rotation:** a database password exposed during setup was reset immediately | Neon role `neondb_owner` |

## Transport and network

| Measure | Where |
|---|---|
| HTTPS for the public API (TLS terminated by Render) | Render |
| **TLS to the database** (`sslmode=require`, `channel_binding=require`) | production `DATABASE_URL` |
| Local PostgreSQL bound to `127.0.0.1` only, not reachable from the network | `docker-compose.yml` |
| Hosting and database in the EU (Frankfurt) | Render, Neon |

## Data layer

| Measure | Where |
|---|---|
| Parameterised queries via SQLAlchemy; no SQL built from strings, which prevents SQL injection | all data access |
| Integrity enforced by the database: foreign keys, composite unique constraints, enums | `app/models/`, `migrations/` |
| Audit log protected against deletion of referenced users, keys and organisations (no `ON DELETE` on its foreign keys) | `app/models/audit.py` |
| Transactions: the seed and migrations are atomic (all or nothing) | `app/seed.py`, Alembic |
| Continuous backups: Neon point-in-time restore | Neon |

## API

| Measure | Where |
|---|---|
| Input validation by FastAPI / Pydantic (422 on malformed requests) | all endpoints |
| Explicit response models: only listed fields are returned | `app/auth/router.py` |
| Internal errors not exposed: database failures return a generic 503 | `app/main.py` |
| Readiness health check used by the host, so a broken version never receives traffic | `/health/ready`, Render |

## Secure development life cycle

| Measure | Where |
|---|---|
| CI on every pull request: lint, formatting, **security lint rules (Bandit rules via Ruff `S`)**, migration round trip, tests | `.github/workflows/ci.yml`, `pyproject.toml` |
| Security lint findings reviewed individually; the one false positive (OAuth2 token type `"bearer"`) is suppressed on that line only, with a documented reason | `app/auth/router.py` |
| CI workflow runs with **least privilege** (`permissions: contents: read`) | `.github/workflows/ci.yml` |
| Pinned dependency versions; development tools kept out of the production requirements | `requirements.txt`, `requirements-dev.txt` |
| Package provenance checked before adding a new dependency (`httpx2`) | PR history |
| Test-first development for security-relevant code (passwords, tokens, login) | git history |
| Branch ruleset for `main`: PR required, CI checks required, force pushes and deletion blocked (configured; not enforced on the free plan for private repos, so the workflow is followed manually) | GitHub settings |
| GitHub access via SSH key with passphrase | developer setup |
| Private repository; assessors invited individually | GitHub settings |
