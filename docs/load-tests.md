# Load tests

Tool: [Locust](https://locust.io) ([`loadtests/locustfile.py`](../loadtests/locustfile.py)), run from a separate virtual environment (`requirements-load.txt`).

## Scenario

A simulated security analyst, authenticated with one bearer token, waits 0.5–1.5 s between requests and calls:

| Endpoint | Weight |
|---|---|
| `GET /organizations/{id}/exposure` (cached) | 3 |
| `GET /organizations/{id}/findings?limit=50` | 2 |
| `GET /organizations/{id}/findings?known_exploited=true` | 1 |

**Data:** 20 products, each with a 12-component SBOM of old PyPI versions and the findings matching creates for them, seeded locally with `python -m loadtests.seed_load_data` (refuses non-local databases); 27,069 vulnerabilities imported from OSV.

**Load:** 100 users, ramped up at 20 per second, 2 minutes per run. Server started without auto-reload, with `LOG_LEVEL=WARNING` and `--no-access-log`.

## Results, 24 November 2026 (local machine)

| | A: 1 process, no cache | B: 1 process, cache | C: 4 processes, cache |
|---|---|---|---|
| exposure: median / 95th percentile | 140 / 460 ms | 81 / 250 ms | 9 / 22 ms |
| findings: median / 95th percentile | 170 / 510 ms | 130 / 310 ms | 46 / 78 ms |
| findings (KEV): median / 95th percentile | 160 / 470 ms | 120 / 310 ms | 36 / 60 ms |
| all requests: median / 95th percentile | 150 / 480 ms | 100 / 290 ms | 31 / 63 ms |
| requests per second | 83.2 | 88.0 | 95.9 |
| failures | 0 | 0 | 0 |

## Interpretation

- **Caching (A → B):** cached exposure responses take as little as 5 ms (one Redis read, no SQL). The uncached endpoints also got faster, because the most frequent request no longer occupies the single process for long.
- **One process is one queue:** in B, a cached response still waits behind slower requests, so the exposure median stays at 81 ms.
- **Scaling out (B → C):** four processes remove the queue; the 95th percentile of all requests drops from 480 ms (A) to 63 ms (C). This works because the application is stateless: identity is in signed tokens, data in PostgreSQL, the cache in Redis, so any process can serve any request.
- **Throughput:** requests per second are limited by the simulated users' think time (about 100 users × 1 request per second), not by the server in run C. Finding C's maximum needs more users.

## Limits of these measurements

- Locust, API, PostgreSQL and Valkey shared one machine (WSL), so the numbers compare setups; they are not production capacity.
- One 2-minute run per setup.
- The login rate limiter kept its counters per process in these runs; with several processes it must use shared storage (Redis).
