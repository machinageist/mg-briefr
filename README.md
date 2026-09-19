# mg-brief

mg-brief is the local-first source, CVE, and asset-observation catalog for the Geist suite.
It owns registered sources, fetched source artifacts, CVE records and history, and immutable
asset observations. It explains and preserves provenance; it never performs remediation.

## MVP workflow

The CLI uses SQLite for catalog state and a separate artifact root:

```text
export MG_BRIEF_DB="$PWD/catalog.sqlite"
export MG_BRIEF_ARTIFACT_ROOT="$PWD/artifacts"

cargo run -- register security-advisories https://example.invalid/feed.xml
cargo run -- sources
cargo run -- fetch security-advisories --max-bytes 1048576 --timeout-seconds 20
cargo run -- export --json > brief-snapshot.json
cargo run -- status
```

Network access is explicit in `fetch`. Requests are bounded by bytes and timeout, redirects
are bounded, private/link-local targets are rejected, and source artifacts retain provenance.
A failed fetch is a recorded failed run, not an implicit fallback.

`status` is read-only: it opens the existing catalog without migrations or recovery and emits
`mg.brief.status/1` with catalog counts. A missing or unreadable catalog is reported as an
explicit unconfigured/unavailable state rather than creating files.

### Ticker and items

mg-feedr (the live headline ticker) and mg-streamr (podcasts) link this crate rather than
fetching feeds themselves, so every feed goes through the same guarded network path.

```text
cargo run -- register wire https://example.invalid/wire.xml --ticker --every 120
cargo run -- ticker wire off            # or: ticker wire on --every 300 (30–86400 s)
cargo run -- items --ticker --limit 20  # newest 20, oldest first
cargo run -- items --since 412          # only items after id 412
```

Fetches are conditional: the stored `ETag` / `Last-Modified` go back to the server, and a 304
records a `not_modified` run and stores nothing. Every attempt, failed or not, counts toward a
ticker source's interval. Items carry a plain-text summary (at most 400 characters), the
enclosure, artwork, and a `has_video` flag (a `video/*` type, or a YouTube, Vimeo,
Dailymotion or Twitch link). Item and enclosure links are handed out only when they are
`http`/`https`, with embedded credentials removed and the query kept.

The library adds `set_ticker`, `due_ticker_sources`, `items` (an id cursor, oldest first),
`feed::parse_feed` (pure), and `fetch_feed_url`, a bounded fetch and parse of any http(s) feed
that stores nothing. The catalog runs in WAL mode, so a daemon and the CLI can share it.

CVE and asset commands are available under `cve` and `asset`:

```text
cargo run -- cve import-cve5 --input RECORD.json --locator https://example.invalid/cve.json --retrieved-at 2026-09-01T00:00:00Z
cargo run -- cve current CVE-2026-0001
cargo run -- cve history CVE-2026-0001
cargo run -- asset import --input asset-observation.json
cargo run -- asset list
cargo run -- asset inspect ASSET-ID
```

All imports validate before persistence. Repeated identical imports are idempotent; immutable
conflicts, invalid provenance, unsafe locators, oversized input, and unsafe identifiers fail
without partial replacement. Asset observations preserve freshness and correction history.

## Verify

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

The CLI and tests use temporary SQLite catalogs and fixture inputs. Network fetches should be
run only against an explicitly authorized source; local/private targets are intentionally
blocked by the fetch safety policy.

## Explicit non-goals

- automatic remediation;
- vulnerability scanning or exploit execution;
- probabilistic risk scoring;
- AI-generated conclusions without cited records;
- dashboards, alerting services, synchronization, or a broad hardware extractor;
- a second inventory authority outside immutable asset observations.

## License

MIT. See `LICENSE`.
