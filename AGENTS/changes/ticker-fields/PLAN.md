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
