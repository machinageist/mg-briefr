<!--
Author: Jeff
Date: 2026-09-18
Description: BR slices, each committed with its gates green
-->

# BR plan

1. Remove the Postgres layer (module, dependency, CLI option, README) → gates.
2. `src/feed.rs`: pure `parse_feed` (enclosures, video detection, images, durations, plain
   summaries) with fixture tests.
3. M5 migration, WAL, Source fields, fetch stores the new item fields, conditional GET,
   `last_fetched_at`, `set_ticker`, `due_ticker_sources`, `items`, `fetch_feed_url` → tests.
4. CLI: `register --ticker`, `ticker`, `items`; README.
5. Back up the live catalog, open it once (M4 → M5), then confirm `mg-brief status` is
   unchanged and the shell still reads it.

## Status (2026-09-19)

Done. Postgres removed 8b22779, parse_feed a3d1c57, M5/WAL/ticker API e9e3c5f, CLI 7e4748e.
The live catalog was backed up to `~/.geistos-reconcile-backups/2026-09-19-mg-brief/`
(`sqlite3 .backup`, integrity ok), then opened once: M1–M5 applied, WAL on, integrity ok,
`mg-brief status` byte-identical before and after, and dotfiles `geist-status.py` reads it.
Not testable end to end here: a real HTTP 304. The SSRF guard refuses loopback, so the
request headers and response validators are unit-tested separately. The `postgres-port`
branch (one WIP commit, 78bfbeb) is untouched.
