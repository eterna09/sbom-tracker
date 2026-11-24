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

## Production smoke test, 25 November 2026

A short, deliberately small run against the live deployment (Render Starter, Neon Free, Render Key Value Free), to check behaviour under modest load without exhausting free-plan resources: 20 users, ramped up at 5 per second, 1 minute, same scenario as above.

| | Median | 95th percentile | Requests per second |
|---|---|---|---|
| exposure | 45 ms | 70 ms | 9.2 |
| findings | 49 ms | 69 ms | 6.5 |
| findings (KEV) | 49 ms | 72 ms | 3.2 |
| **all** | **47 ms** | **70 ms** | **19.0** |

1,123 requests, 1 failure (0.09 %): a connection closed without a response (`RemoteDisconnected`), with no 5xx in the application log, i.e. at the network layer, not an application error.

The production database holds little product data (load-test data is only ever seeded locally), so these times mainly reflect the request path: TLS from Berlin to Frankfurt, Render's proxy, the application, and the round trip to Neon.

## Scaling

- **Stateless application:** identity lives in signed tokens, data in PostgreSQL, the cache and the login rate-limit counters in Redis (Valkey). Any process or instance can serve any request, so the service scales out by adding uvicorn workers or Render instances (run C: 4 workers cut the 95th percentile from 290 ms to 63 ms).
- **Shared rate limiting:** login counters are kept in Redis (`RATE_LIMIT_STORAGE_URL`), so limits hold across processes and instances; with per-process memory, 4 processes would have allowed 4 × the intended attempts.
- **Next bottlenecks when scaling further:** database connections (each process keeps its own pool, and Neon limits connections per compute), Neon compute size (0.25–2 CU autoscaling on the current plan), and the per-component queries in the SBOM upload (planned: batch loading).
- **What was not scaled:** the vulnerability import runs as a single command-line job; it is write-heavy and runs rarely, so it is optimised for throughput (batching) rather than parallelism.
