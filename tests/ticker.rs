// Author: Jeff
// Date: 2026-09-18
// Description: The ticker and podcast fields end to end — migrate, fetch, store, list, schedule
// Notes: Feeds are file:// fixtures read in trusted fixture mode, so nothing touches the network.
//        Each test builds its own catalog in a temp dir

use chrono::{Duration, Utc};
use mg_brief::{fetch_feed_url, ItemQuery, Store, MIGRATIONS};
use rusqlite::{params, Connection};
use std::fs;
use std::path::Path;
use url::Url;

const HEADLINES: &str = r#"<?xml version="1.0"?>
<rss version="2.0"><channel><title>Wire</title>
<item><title>First</title><guid>a</guid><link>https://news.example/a?id=1</link>
<description>&lt;b&gt;Big&lt;/b&gt; news</description></item>
<item><title>Clip</title><guid>b</guid><link>https://www.youtube.com/watch?v=xyz</link></item>
<item><title>Sneaky</title><guid>c</guid><link>javascript:alert(1)</link></item>
</channel></rss>"#;

const PODCAST: &str = r#"<?xml version="1.0"?>
<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd"><channel><title>Show</title>
<item><title>Ep</title><guid>ep</guid><link>https://pod.example/ep</link>
<enclosure url="https://user:secret@cdn.example/ep.mp3?token=t" type="audio/mpeg" length="10"/>
<itunes:image href="https://cdn.example/ep.jpg"/></item>
</channel></rss>"#;

// A catalog with a fixtures folder it may read file:// feeds from
fn store_with(dir: &Path, feeds: &[(&str, &str)]) -> Store {
    let fixtures = dir.join("fixtures");
    fs::create_dir_all(&fixtures).unwrap();
    for (name, body) in feeds {
        fs::write(fixtures.join(name), body).unwrap();
    }
    Store::open_with_trusted_file_root(dir.join("catalog.sqlite"), dir.join("artifacts"), &fixtures)
        .expect("catalog opens")
}

// The file:// URL of a fixture
fn fixture_url(dir: &Path, name: &str) -> String {
    let path = fs::canonicalize(dir.join("fixtures").join(name)).unwrap();
    Url::from_file_path(path).unwrap().to_string()
}

#[test]
fn a_fetch_stores_summaries_enclosures_art_and_the_video_flag() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_with(dir.path(), &[("wire.xml", HEADLINES), ("pod.xml", PODCAST)]);
    store
        .register("wire", &fixture_url(dir.path(), "wire.xml"), None)
        .unwrap();
    store
        .register("pod", &fixture_url(dir.path(), "pod.xml"), None)
        .unwrap();
    assert_eq!(store.fetch("wire", 1 << 20, 5).unwrap().items, 3);
    assert_eq!(store.fetch("pod", 1 << 20, 5).unwrap().items, 1);

    let items = store
        .items(&ItemQuery {
            limit: 50,
            ..Default::default()
        })
        .unwrap();
    let by_title = |t: &str| items.iter().find(|i| i.title == t).unwrap();
    assert_eq!(by_title("First").summary.as_deref(), Some("Big news"));
    assert_eq!(
        by_title("First").url.as_deref(),
        Some("https://news.example/a?id=1"),
        "the query survives — opening needs it"
    );
    assert!(by_title("Clip").has_video);
    assert_eq!(
        by_title("Sneaky").url,
        None,
        "a javascript: link is never handed out"
    );
    let ep = by_title("Ep");
    assert_eq!(
        ep.enclosure_url.as_deref(),
        Some("https://cdn.example/ep.mp3?token=t"),
        "credentials go, the token stays"
    );
    assert_eq!(ep.enclosure_type.as_deref(), Some("audio/mpeg"));
    assert_eq!(ep.image_url.as_deref(), Some("https://cdn.example/ep.jpg"));
    assert_eq!(ep.source, "pod");
}

#[test]
fn the_cursor_returns_only_newer_items_oldest_first_and_filters_apply() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_with(dir.path(), &[("wire.xml", HEADLINES), ("pod.xml", PODCAST)]);
    store
        .register("wire", &fixture_url(dir.path(), "wire.xml"), None)
        .unwrap();
    store
        .register("pod", &fixture_url(dir.path(), "pod.xml"), None)
        .unwrap();
    store.fetch("wire", 1 << 20, 5).unwrap();
    store.fetch("pod", 1 << 20, 5).unwrap();

    let all = store
        .items(&ItemQuery {
            limit: 50,
            ..Default::default()
        })
        .unwrap();
    let ids: Vec<i64> = all.iter().map(|i| i.id).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "oldest first");
    let newest_two = store
        .items(&ItemQuery {
            limit: 2,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        newest_two.iter().map(|i| i.id).collect::<Vec<_>>(),
        ids[ids.len() - 2..]
    );
    let after = store
        .items(&ItemQuery {
            since: Some(ids[1]),
            limit: 50,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(after.iter().map(|i| i.id).collect::<Vec<_>>(), ids[2..]);

    assert!(store
        .items(&ItemQuery {
            ticker_only: true,
            limit: 50,
            ..Default::default()
        })
        .unwrap()
        .is_empty());
    store.set_ticker("pod", true, None).unwrap();
    let ticker = store
        .items(&ItemQuery {
            ticker_only: true,
            limit: 50,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(ticker.len(), 1);
    let wire = store
        .items(&ItemQuery {
            source: Some("wire".into()),
            limit: 50,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(wire.len(), 3);
}

#[test]
fn refetching_keeps_identity_and_fills_missing_fields_without_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_with(dir.path(), &[("wire.xml", HEADLINES)]);
    store
        .register("wire", &fixture_url(dir.path(), "wire.xml"), None)
        .unwrap();
    store.fetch("wire", 1 << 20, 5).unwrap();
    // an item stored before M5 had no summary; the next fetch fills it
    let c = Connection::open(dir.path().join("catalog.sqlite")).unwrap();
    c.execute("UPDATE feed_items SET summary=NULL", []).unwrap();
    store.fetch("wire", 1 << 20, 5).unwrap();
    let items = store
        .items(&ItemQuery {
            limit: 50,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(items.len(), 3, "same items, no duplicates");
    assert_eq!(items[0].summary.as_deref(), Some("Big news"));
}

#[test]
fn due_sources_follow_their_interval_and_every_attempt_counts() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_with(dir.path(), &[("wire.xml", HEADLINES)]);
    store
        .register("wire", &fixture_url(dir.path(), "wire.xml"), None)
        .unwrap();
    assert!(
        store.due_ticker_sources(Utc::now()).unwrap().is_empty(),
        "not on the ticker yet"
    );
    let source = store.set_ticker("wire", true, Some(60)).unwrap();
    assert!(source.ticker);
    assert_eq!(source.fetch_interval_seconds, 60);
    assert_eq!(
        store.due_ticker_sources(Utc::now()).unwrap().len(),
        1,
        "never tried = due"
    );

    store.fetch("wire", 1 << 20, 5).unwrap();
    assert!(
        store.due_ticker_sources(Utc::now()).unwrap().is_empty(),
        "just asked"
    );
    assert_eq!(
        store
            .due_ticker_sources(Utc::now() + Duration::seconds(61))
            .unwrap()
            .len(),
        1
    );

    // a failed attempt counts too, so a broken source is not hammered every tick
    fs::remove_file(dir.path().join("fixtures/wire.xml")).unwrap();
    let failed = store.fetch("wire", 1 << 20, 5).unwrap();
    assert_eq!(failed.status, "failed");
    assert!(store.due_ticker_sources(Utc::now()).unwrap().is_empty());

    assert!(
        store.set_ticker("wire", true, Some(5)).is_err(),
        "too often"
    );
    assert!(store.set_ticker("nope", true, None).is_err());
}

#[test]
fn an_m4_catalog_upgrades_in_place_and_turns_on_wal() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.sqlite");
    // build a catalog exactly as the M4 release left it
    let c = Connection::open(&db).unwrap();
    c.execute_batch("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, checksum TEXT);")
        .unwrap();
    for m in &MIGRATIONS[..4] {
        c.execute_batch(m.sql).unwrap();
        c.execute(
            "INSERT INTO schema_migrations(version,checksum) VALUES (?1,?2)",
            params![m.version, m.checksum],
        )
        .unwrap();
    }
    c.execute("INSERT INTO sources(name,url,user_agent,created_at) VALUES ('old','https://old.example/feed','ua','2026-01-01T00:00:00+00:00')", []).unwrap();
    c.execute("INSERT INTO feed_items(source_id,identity_key,guid,url,title,published_at,first_seen_at) VALUES (1,'guid\u{1f}x','x','https://old.example/x','Old news',NULL,'2026-01-01T00:00:00+00:00')", []).unwrap();
    drop(c);

    let store = Store::open(&db, dir.path().join("artifacts")).expect("upgrades");
    let old = store.source_by_name("old").unwrap();
    assert!(!old.ticker);
    assert_eq!(old.fetch_interval_seconds, 300);
    let items = store
        .items(&ItemQuery {
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(items[0].title, "Old news");
    assert!(!items[0].has_video);

    let c = Connection::open(&db).unwrap();
    let mode: String = c
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let versions: i64 = c
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(versions, MIGRATIONS.len() as i64);
}

#[test]
fn fetch_feed_url_refuses_files_and_private_addresses() {
    assert!(fetch_feed_url("file:///etc/passwd", None, 1024, 5).is_err());
    assert!(fetch_feed_url("http://127.0.0.1/feed", None, 1024, 5).is_err());
    assert!(fetch_feed_url("http://169.254.169.254/latest", None, 1024, 5).is_err());
    assert!(fetch_feed_url("https://example.com/feed", Some("bad\r\nua"), 1024, 5).is_err());
    assert!(fetch_feed_url("https://example.com/feed", None, 0, 5).is_err());
}
