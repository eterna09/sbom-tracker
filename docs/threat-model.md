# Threat Model

Method: **STRIDE** (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege), applied per trust boundary.

Status legend: **Implemented**, **Partly**, **Planned**. This document reflects the current state of the code and is updated as features are merged.

## 1. System overview

```mermaid
flowchart LR
    subgraph Internet["Untrusted: Internet"]
        Analyst["Security team user<br/>(browser / API client)"]
        CI["Manufacturer CI pipeline"]
        Attacker["Attacker"]
    end

    subgraph Render["Trusted: Render (PaaS)"]
        API["FastAPI application"]
    end

    subgraph Neon["Trusted: Neon (managed PostgreSQL)"]
        DB[("Database")]
    end

    subgraph Supply["Supply chain"]
        GH["GitHub repo + Actions"]
        PyPI["PyPI packages"]
        Feeds["OSV / CISA KEV feeds"]
    end

    Analyst -- "TB1: HTTPS" --> API
    CI -- "TB1: HTTPS" --> API
    Attacker -. "TB1" .-> API
    API -- "TB2: TLS" --> DB
    GH -- "TB3: deploy" --> API
    PyPI -- "TB3: dependencies" --> API
    Feeds -- "TB4: imported data" --> API
```

**Trust boundaries:**
- **TB1:** Internet → API. All client input is untrusted.
- **TB2:** API → database.
- **TB3:** source code, dependencies and the deployment pipeline (supply chain).
- **TB4:** external vulnerability data (OSV, CISA KEV) imported into the database by command-line jobs.

## 2. Assets

| Asset | Why it matters |
|---|---|
| User credentials (password hashes) | Account takeover if cracked |
| Token signing key (`JWT_SECRET_KEY`) | Anyone holding it can forge tokens for any user |
| Database credentials (`DATABASE_URL`) | Full read/write access to all data |
| Organisation data: products, SBOMs, findings | Confidential. Reveals which products are vulnerable; must stay separated between organisations |
| CRA report deadlines | Integrity matters: wrong deadlines could cause missed legal reporting obligations |
| Audit log | Evidence of who did what; must not be altered or deleted |
| Availability of the API | Manufacturers depend on it during an incident, when deadlines run in hours |

## 3. Threats and mitigations

### Spoofing (pretending to be someone else)

| Threat | Mitigation | Status |
|---|---|---|
| Attacker guesses or reuses a user's password | Passwords stored only as Argon2id hashes, verified via a library; no custom crypto | Implemented |
| Attacker forges an access token | Tokens signed with HS256 and a 64-byte random secret; the server pins the accepted algorithm; `sub`, `iat`, `exp` required | Implemented |
| `alg: none` / algorithm-confusion attack | Accepted algorithm fixed server-side (`algorithms=["HS256"]`); covered by a test | Implemented |
| Stolen token used indefinitely | Short token lifetime (30 minutes by default) | Implemented |
| Attacker discovers which emails have accounts (user enumeration) | Identical 401 response for unknown email and wrong password; for unknown emails a dummy Argon2 verification equalises response time | Implemented |
| Online password brute force, including attacks spread over many IPs | Login rate limiting: 10 attempts per minute per client IP and 5 per minute per account (moving window), 429 with `Retry-After`; see accepted risks for the limits of this | Implemented |
| Stolen CI API key used to upload SBOMs | API keys stored only as hashes, scoped to one organisation, revocable (`revoked_at`) | Implemented |

### Tampering (changing data or code)

| Threat | Mitigation | Status |
|---|---|---|
| SQL injection | All queries built with SQLAlchemy (parameterised); no string-built SQL | Implemented |
| Malformed or malicious input | Request validation via Pydantic / FastAPI; 422 on invalid input | Implemented (login); extended per endpoint |
| Malicious or oversized SBOM upload | Size limit, schema validation of CycloneDX JSON, upload only via organisation API key | Partly (size limit via declared Content-Length, CycloneDX schema validation; chunked requests without Content-Length are not limited by the app) |
| Inconsistent data after partial failures | Transactions: seed, migrations, each import batch, and SBOM upload together with matching are atomic | Implemented |
| Duplicate or contradictory records | Unique and foreign key constraints enforced by the database itself | Implemented |
| Unreviewed code reaching production | Pull requests with CI (lint, security rules, dependency audit, migration round trip, tests) before merge to `main` | Implemented (ruleset configured; not enforced on the free plan for private repos) |
| Compromised or vulnerable dependency | Pinned versions; provenance checked before adding packages; `pip-audit` against OSV in CI; Dependabot for pip and GitHub Actions | Implemented |
| Tampered vulnerability feed data | Downloaded over HTTPS from the official sources (OSV, CISA); the importers read only the expected fields and reject records without them | Partly (no signature verification; the feeds don't offer signatures) |

### Repudiation (denying an action)

| Threat | Mitigation | Status |
|---|---|---|
| User denies having triaged a finding as "not affected" | `triaged_by_id` stored on the finding; justification required for "not affected" | Planned (schema implemented) |
| Actions cannot be traced afterwards | Append-only audit log (logins, uploads, triage, key use). The database blocks deleting users, keys or organisations that appear in it | Planned (schema implemented, including the deletion protection) |

### Information disclosure

| Threat | Mitigation | Status |
|---|---|---|
| One organisation reads another's products or findings | One central access dependency resolves user + organisation + role for every organisation-scoped request | Implemented (get_current_access, IDOR test) |
| Sensitive fields leak in API responses | Explicit Pydantic response models list exactly the fields returned | Implemented (login); applied to every new endpoint |
| Internal errors reveal details | Database errors mapped to generic responses (e.g. readiness returns "database unavailable"); token errors collapsed into one generic 401 | Implemented |
| Secrets in the repository | `.env` git-ignored; `.env.example` holds placeholders only; production secrets stored in Render's environment settings; separate secrets per environment | Implemented |
| Eavesdropping on traffic | HTTPS to the API (Render); TLS to the database (`sslmode=require`, channel binding) | Implemented |
| Local database exposed on the network | Docker Compose binds PostgreSQL to `127.0.0.1` only | Implemented |
| Token contents readable | JWTs are signed, not encrypted, so they contain only the user id and timestamps, nothing confidential | Implemented (by design) |

### Denial of service

| Threat | Mitigation | Status |
|---|---|---|
| Login flood exhausts CPU (Argon2 is deliberately expensive) | Rate limit checked before the password hash, so blocked attempts cost no hashing | Implemented |
| Flood of requests / expensive endpoints | Caching of the exposure summary; load tests to find bottlenecks; rate limits beyond login | Planned |
| Huge uploads exhaust memory | Request size limits on SBOM upload | Partly (see SBOM upload above) |
| Broken deployment takes the API down | Health check on `/health/ready`: Render only switches to a new version once the app and database are reachable | Implemented |
| Data loss | Neon continuous point-in-time restore | Implemented (restore test planned) |

### Elevation of privilege

| Threat | Mitigation | Status |
|---|---|---|
| Viewer performs analyst or admin actions | Role checks per organisation membership, enforced in the central access dependency | Implemented |
| Over-privileged CI pipeline | GitHub Actions workflow runs with `permissions: contents: read` (least privilege) | Implemented |
| Compromised developer machine pushes to production | Private repository; SSH key with passphrase; production secrets not stored on the developer machine | Implemented |

## 4. Accepted risks and open points

- **Branch protection not enforced:** GitHub does not enforce rulesets on private repositories on the free plan. The workflow (PR + green CI before merge) is followed manually.
- **Neon free plan history window is 6 hours:** enough to undo recent mistakes, not for long-term recovery. Upgrading to a longer window is possible at any time.
- **Credential exposure during setup:** a database password was exposed once during deployment. It was rotated immediately, and secrets are now entered through hidden terminal input only.
- **Rate-limit counters live in process memory:** they reset on every restart, and with several instances each would count separately. Planned fix: Redis storage (one-line change in `app/auth/rate_limit.py`) together with caching.
- **Client IP can be spoofed:** on Render the app trusts `X-Forwarded-For` from any source (Render does not publish fixed proxy addresses), so an attacker can bypass the per-IP limit. The per-account limit does not depend on the IP and still applies.
- **Short account lockout possible:** an attacker who knows an email can block logins for that account for up to one minute at a time. Accepted, because the window is short and the limit still cuts guessing to 5 attempts per minute.
- **No secret scanning:** GitHub secret scanning for private repositories needs a paid plan. Mitigated by process (`.env` git-ignored, hidden input, rotation on exposure); the `sbom_` key prefix allows scanning with custom patterns if it becomes available.
- **Unparsable versions are treated as not affected:** this avoids false alarms from malformed SBOM or OSV data, but a malformed version string can hide a real vulnerability (false negative). Mitigation planned: count and report skipped evaluations.
