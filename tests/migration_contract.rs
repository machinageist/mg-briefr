use mg_brief::{migration_status, Store, MIGRATIONS};
use rusqlite::Connection;

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir().expect("scratch directory")
}

fn open(dir: &tempfile::TempDir) -> anyhow::Result<Store> {
    Store::open(
        dir.path().join("catalog.sqlite"),
        dir.path().join("artifacts"),
    )
}

#[test]
fn every_embedded_migration_matches_its_own_checksum() {
    use sha2::{Digest, Sha256};
    for migration in MIGRATIONS {
        let digest: String = Sha256::digest(migration.sql.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest, migration.checksum,
            "migration {} ('{}') SQL and checksum disagree",
            migration.version, migration.name
        );
    }
}

#[test]
fn migration_versions_are_contiguous_and_declare_the_tables_they_create() {
    for (index, migration) in MIGRATIONS.iter().enumerate() {
        assert_eq!(migration.version, index as i64 + 1);
        for table in migration.tables {
            assert!(
                migration.sql.contains(&format!("CREATE TABLE {table}")),
                "migration {} claims table '{table}' it does not create",
                migration.version
            );
        }
    }
}

#[test]
fn a_fresh_catalog_applies_every_migration_and_records_its_checksum() {
    let dir = scratch();
    open(&dir).expect("fresh catalog opens");

    let connection = Connection::open(dir.path().join("catalog.sqlite")).unwrap();
    let recorded: Vec<(i64, Option<String>)> = connection
        .prepare("SELECT version, checksum FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert_eq!(recorded.len(), MIGRATIONS.len());
    for (migration, (version, checksum)) in MIGRATIONS.iter().zip(recorded) {
        assert_eq!(version, migration.version);
        assert_eq!(checksum.as_deref(), Some(migration.checksum));
    }
    assert!(migration_status(&connection)
        .unwrap()
        .iter()
        .all(|m| m.applied));
}

#[test]
fn reopening_an_unchanged_catalog_is_idempotent() {
    let dir = scratch();
    open(&dir).expect("first open");
    open(&dir).expect("second open");
    open(&dir).expect("third open");
}

#[test]
fn a_migration_edited_after_it_was_applied_is_refused() {
    let dir = scratch();
    open(&dir).expect("fresh catalog opens");

    // Exactly the failure that left the real catalog broken: the ledger keeps
    // saying "applied" while the recorded SQL no longer matches what shipped.
    let connection = Connection::open(dir.path().join("catalog.sqlite")).unwrap();
    connection
        .execute(
            "UPDATE schema_migrations SET checksum='0000' WHERE version=3",
            [],
        )
        .unwrap();
    drop(connection);

    let error = open(&dir).expect_err("a rewritten migration must be refused");
    let message = error.to_string();
    assert!(message.contains("schema migration 3"), "{message}");
    assert!(
        message.contains("changed after it was applied"),
        "{message}"
    );
}

#[test]
fn a_legacy_row_without_a_checksum_is_judged_on_the_live_schema() {
    let dir = scratch();
    open(&dir).expect("fresh catalog opens");
    let path = dir.path().join("catalog.sqlite");

    // A pre-checksum ledger whose tables are all present is trusted and upgraded
    let connection = Connection::open(&path).unwrap();
    connection
        .execute("UPDATE schema_migrations SET checksum=NULL", [])
        .unwrap();
    drop(connection);
    open(&dir).expect("an intact legacy catalog is adopted");

    let connection = Connection::open(&path).unwrap();
    let missing: i64 = connection
        .query_row(
            "SELECT count(*) FROM schema_migrations WHERE checksum IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(missing, 0, "checksums are backfilled once verified");
    drop(connection);

    // The real defect: recorded as applied, but the tables were never created
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "UPDATE schema_migrations SET checksum=NULL WHERE version=3; \
             DROP TABLE cve_current;",
        )
        .unwrap();
    drop(connection);

    let error = open(&dir).expect_err("a recorded migration with missing tables must be refused");
    let message = error.to_string();
    assert!(message.contains("schema migration 3"), "{message}");
    assert!(message.contains("cve_current"), "{message}");
}

#[test]
fn a_ledger_with_a_gap_is_refused() {
    let dir = scratch();
    open(&dir).expect("fresh catalog opens");

    let connection = Connection::open(dir.path().join("catalog.sqlite")).unwrap();
    connection
        .execute("DELETE FROM schema_migrations WHERE version=2", [])
        .unwrap();
    drop(connection);

    let error = open(&dir).expect_err("a non-contiguous ledger must be refused");
    assert!(error.to_string().contains("inconsistent"), "{error}");
}
