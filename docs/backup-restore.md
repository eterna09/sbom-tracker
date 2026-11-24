# Backup and restore

## Backup configuration

- **Provider:** Neon (managed PostgreSQL 17), region AWS Europe Central 1 (Frankfurt), Free plan
- **Method:** continuous point-in-time recovery from Neon's retained write-ahead log (WAL); no nightly dump files
- **History window:** 6 hours (Free plan maximum, capped at 1 GB of changes); any moment inside the window can be restored
- **Restore options:** rewind the production branch in place (instant restore), or create a new branch from a past point in time and inspect it first (used here, because it never touches production)

## Restore drill, 24 November 2026

**Goal:** prove that data deleted by mistake can be recovered, and measure how long it takes.

| Step | Time (UTC) | Action | Result |
|---|---|---|---|
| 1 | 20:07:03 | Created a scratch table `restore_drill` with 2 rows on `production`; recorded reference values | 2 rows; 27,069 vulnerabilities; migration `1fbbee325bf0` |
| 2 | ~20:10 | Simulated the accident: `DELETE FROM restore_drill` | 0 rows on `production` |
| 3 | ~20:13 | Created branch `restore-drill-2026-11-24` from `production` at **20:08:00** (between steps 1 and 2) | Branch and compute available within seconds |
| 4 | 20:18:32 | Queried the restored branch | 2 rows with both notes; 27,069 vulnerabilities; migration `1fbbee325bf0` |
| 5 | after 20:18 | Dropped the scratch table on `production`; deleted the drill branch | Production unchanged apart from the scratch table |

**Result:** the restored branch matched the reference state exactly: the deleted rows were back, and the real data and the schema version were identical.

- **Recovery point (RPO):** any moment inside the 6-hour window; here, a point chosen to the second between the last good state and the mistake
- **Recovery time (RTO):** the branch was available within seconds; the full drill took about 5½ minutes from creating the branch to verified data, mostly navigating the console for the first time

**Safety measures during the drill:** a scratch table instead of real data; all SQL run in the Neon Console, so the production connection string never left Neon; the restored copy was checked on a separate branch before anything else.

## Limits

- The 6-hour window covers recent mistakes, not problems discovered later. A paid plan extends it to 7 or 30 days.
- The Free plan includes one manual snapshot, which can keep a state beyond the window (for example before a risky migration).
- To bring restored data back into `production`, either rewind `production` itself (instant restore) or copy the needed rows from the restore branch.
