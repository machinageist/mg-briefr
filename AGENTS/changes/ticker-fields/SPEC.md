<!--
Author: Jeff
Date: 2026-09-18
Description: mg-brief grows what a live ticker and a podcast player need, and drops the unfinished Postgres port
Notes: Geistos cycle 02, slice BR. Decided with Jeff 2026-09-18: the suite stays on SQLite and
       server-free; mg-feedr (ticker) links mg-brief as a library; mg-streamr owns podcast data but
       reuses mg-brief's bounded fetch and parse
-->

# BR — ticker fields, feed parsing for consumers, no Postgres

## Why

mg-feedr streams headlines from sources marked for the ticker, and mg-streamr needs podcast
enclosures. Both should share mg-brief's hardened network path (SSRF checks, pinned DNS,
byte limits, redirect limits) rather than growing their own.

## Outcome

- The half-built Postgres path is gone: `src/postgres.rs`, the `postgres` dependency and the
  `--database-url` / `MG_BRIEF_DATABASE_URL` option. The `postgres-port` branch is untouched.
- An append-only migration (M5) adds:
  - on sources: `ticker` (default 0), `fetch_interval_seconds` (default 300), `etag`,
    `last_modified`, `last_fetched_at`;
  - on feed items: plain-text `summary` (at most 400 chars), `enclosure_url`, `enclosure_type`,
    `image_url`, `has_video` (0/1).
  Earlier migrations and their checksums do not change.
- The catalog runs in WAL mode, so a ticker daemon and the CLI can share it.
- A fetch is conditional (`If-None-Match` / `If-Modified-Since`). A 304 records a
  `not_modified` run and stores nothing new. Every fetch records `last_fetched_at`.
- A video item is one with a `video/*` enclosure or media content, or whose link is on a known
  video host (YouTube, Vimeo, Dailymotion, Twitch).
- Library API: `set_ticker`, `due_ticker_sources`, `items` (cursor = item id, ascending),
  `parse_feed` (pure), and `fetch_feed_url`, a bounded fetch and parse of any http(s) URL that
  stores nothing and returns entries with enclosures, images and durations.
- CLI: `register … --ticker`, `ticker <name> on|off [--every <seconds>]`, and
  `items [--since <id>] [--ticker] [--source <name>] [--limit <n>]`.

## Constraints

- `mg-brief status` output stays byte-identical. The shell's GeistStatus and geist-alerts
  read it.
- Nothing weakens the network guards; conditional GET only adds request headers.
- rusqlite stays at 0.32 (mg-feedr and mg-streamr link this crate).
- Back up the live catalog before the first M5 open.

## Acceptance

- Gates: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
- Fixture tests: RSS enclosure, iTunes image and duration, Atom enclosure link, YouTube link
  gives `has_video`, HTML summary becomes plain bounded text, 304 handling, the items cursor,
  due-source selection, and a fresh catalog plus an M4 catalog both migrating to M5.
