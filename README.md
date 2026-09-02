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
```

Network access is explicit in `fetch`. Requests are bounded by bytes and timeout, redirects
are bounded, private/link-local targets are rejected, and source artifacts retain provenance.
A failed fetch is a recorded failed run, not an implicit fallback.

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
