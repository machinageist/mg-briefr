use anyhow::{bail, Context, Result};
use rusqlite::{types::ValueRef, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
use url::Url;

const CATALOG_TABLES: &[&str] = &[
    "schema_migrations",
    "sources",
    "fetch_runs",
    "artifacts",
    "feed_items",
    "provenance",
    "artifact_owners",
    "cve_versions",
    "cve_current",
    "cve_version_provenance",
    "asset_records",
    "asset_observations",
    "item_content",
    "lost_and_found",
];
const LOSS_TOLERANT_TABLES: &[&str] = &["sources", "fetch_runs", "artifacts", "provenance"];
const SIDECAR_SUFFIXES: &[&str] = &["-wal", "-shm", "-journal"];
const MAX_SOURCE_DATABASE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RECOVERY_SQL_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CANDIDATE_DATABASE_BYTES: u64 = 1024 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const SQLITE3_PATH: &str = "/usr/bin/sqlite3";
const TIMEOUT_PATH: &str = "/usr/bin/timeout";
const PRLIMIT_PATH: &str = "/usr/bin/prlimit";
const RECOVERY_TIMEOUT: &str = "300s";
const MAX_SEED_MANIFEST_BYTES: u64 = 1024 * 1024;
const SEED_MANIFEST_SCHEMA: &str = "mg-feedr.historical-seeds/1";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedManifest {
    schema: String,
    source_count: usize,
    sources: Vec<HistoricalFeed>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalFeed {
    name: String,
    url: String,
    every_seconds: i64,
}

#[derive(Clone, Debug)]
struct SourceIdentity {
    id: i64,
    name: String,
    name_was_integer: bool,
    url: String,
}

#[derive(Clone, Debug, Default)]
struct SourceOverride {
    name: Option<String>,
    url: Option<String>,
    enabled: Option<i64>,
    ticker: Option<i64>,
    fetch_interval_seconds: Option<i64>,
}

#[derive(Clone, Debug, Default)]
struct SourceTransform {
    overrides: BTreeMap<i64, SourceOverride>,
    disambiguated_names: usize,
    normalized_name_types: usize,
    restored_urls: usize,
}

#[derive(Debug, Serialize)]
struct HistoricalSeedDiagnostic {
    name: String,
    source_ids: Vec<HistoricalSeedSourceIdDiagnostic>,
}

#[derive(Debug, Serialize)]
struct HistoricalSeedSourceIdDiagnostic {
    source_id: i64,
    source_row_present: bool,
    historical_name_matches: bool,
    historical_url_matches: bool,
    fetch_runs: u64,
    feed_items: u64,
    provenance_rows: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "rows", rename_all = "snake_case")]
enum RowCount {
    Absent,
    Rows(i64),
    Unreadable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TableObservation {
    rows: RowCount,
    digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileVersion {
    length: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

impl FileVersion {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                length: metadata.len(),
                modified: metadata.modified().ok(),
                device: metadata.dev(),
                inode: metadata.ino(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                length: metadata.len(),
                modified: metadata.modified().ok(),
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct TableCountComparison {
    table: &'static str,
    original: RowCount,
    recovered: RowCount,
    exact_records_match: bool,
}

#[derive(Debug, Serialize)]
struct ForeignKeyViolationSummary {
    child_table: String,
    parent_table: String,
    rows: u64,
}

#[derive(Debug)]
struct SourceUniqueIndexSummary {
    index_name: String,
    key_columns: Vec<String>,
    key_collations: Vec<String>,
    duplicate_groups: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct RecoveryReport {
    schema: &'static str,
    status: &'static str,
    recovery_directory: PathBuf,
    backup_database: PathBuf,
    candidate_database: PathBuf,
    original_integrity: &'static str,
    original_integrity_findings: Vec<String>,
    candidate_integrity: super::integrity::IntegrityReport,
    foreign_keys_valid: bool,
    foreign_key_violations: Option<Vec<ForeignKeyViolationSummary>>,
    application_opened_candidate: bool,
    application_opened_installed: bool,
    exact_records_preserved: bool,
    source_rows_reconstructed: bool,
    source_rows_digest_sha256: Option<String>,
    source_snapshot_rows_digest_sha256: Option<String>,
    source_reconstruction_warning: Option<String>,
    source_names_disambiguated: usize,
    source_name_types_normalized: usize,
    source_urls_restored: usize,
    historical_seed_count: Option<usize>,
    historical_seed_set_complete: Option<bool>,
    historical_seed_diagnostics: Option<Vec<HistoricalSeedDiagnostic>>,
    provenance_rows_pruned: u64,
    record_loss_override_used: bool,
    counts: Vec<TableCountComparison>,
    applied: bool,
    durability_warning: Option<String>,
}

#[derive(Debug)]
struct InstalledReadback {
    application_opened: bool,
    integrity: super::integrity::IntegrityReport,
    comparisons: Vec<TableCountComparison>,
    exact_records_preserved: bool,
    record_state_valid: bool,
    approved_record_loss: bool,
    source_rows_accepted: bool,
    historical_seed_set_complete: bool,
    foreign_keys_valid: bool,
    foreign_key_violations: Vec<ForeignKeyViolationSummary>,
    no_unmapped_rows: bool,
}

impl InstalledReadback {
    fn is_valid(&self) -> bool {
        self.application_opened
            && self.integrity.is_healthy()
            && self.record_state_valid
            && (self.exact_records_preserved || self.approved_record_loss)
            && self.source_rows_accepted
            && self.historical_seed_set_complete
            && self.foreign_keys_valid
            && self.no_unmapped_rows
    }
}

pub struct IntegritySnapshot {
    directory: PathBuf,
    database: PathBuf,
}

impl IntegritySnapshot {
    pub fn database_path(&self) -> &Path {
        &self.database
    }
}

impl Drop for IntegritySnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

// Read and validate a bounded historical seed manifest without following symlinks
fn load_seed_manifest(path: &Path) -> Result<SeedManifest> {
    let path_before = fs::symlink_metadata(path)?;
    if !path_before.is_file() || path_before.file_type().is_symlink() {
        bail!("seed manifest must be a regular file");
    }
    let mut file = File::open(path)?;
    let file_before = file.metadata()?;
    if FileVersion::from_metadata(&path_before) != FileVersion::from_metadata(&file_before) {
        bail!("seed manifest changed while opening it");
    }
    if file_before.len() > MAX_SEED_MANIFEST_BYTES {
        bail!("seed manifest exceeds the configured input limit");
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_SEED_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let file_after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    if bytes.len() as u64 > MAX_SEED_MANIFEST_BYTES
        || FileVersion::from_metadata(&file_before) != FileVersion::from_metadata(&file_after)
        || FileVersion::from_metadata(&path_after) != FileVersion::from_metadata(&file_before)
    {
        bail!("seed manifest changed while reading it");
    }
    let manifest: SeedManifest = serde_json::from_slice(&bytes).context("parse seed manifest")?;
    validate_seed_manifest(&manifest)?;
    Ok(manifest)
}

// Reject ambiguous or unsafe source expectations before opening the live catalog
fn validate_seed_manifest(manifest: &SeedManifest) -> Result<()> {
    if manifest.schema != SEED_MANIFEST_SCHEMA
        || manifest.source_count != manifest.sources.len()
        || manifest.sources.is_empty()
        || manifest.sources.len() > 512
    {
        bail!("seed manifest has an unsupported schema or inconsistent source count");
    }
    let mut names = BTreeSet::new();
    let mut urls = BTreeSet::new();
    for source in &manifest.sources {
        if source.name.is_empty()
            || source.name.trim() != source.name
            || source.name.len() > 256
            || source.name.chars().any(char::is_control)
            || !(30..=86_400).contains(&source.every_seconds)
        {
            bail!("seed manifest contains an invalid source name or interval");
        }
        let parsed = Url::parse(&source.url).context("seed manifest contains an invalid URL")?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.as_str() != source.url
        {
            bail!("seed manifest URL must be canonical HTTP(S) without credentials or fragments");
        }
        if !names.insert(source.name.as_str()) || !urls.insert(source.url.as_str()) {
            bail!("seed manifest contains duplicate source names or URLs");
        }
    }
    Ok(())
}

// Make a private, writer-quiesced copy for no-side-effect integrity inspection
pub fn snapshot_for_integrity(
    database: &Path,
    acknowledge_offline: bool,
) -> Result<IntegritySnapshot> {
    if !acknowledge_offline {
        bail!("stop every catalog writer and pass --acknowledge-offline before inspection");
    }
    ensure_regular_file(database)?;
    if fs::symlink_metadata(database)?.len() > MAX_SOURCE_DATABASE_BYTES {
        bail!("catalog exceeds the configured inspection input limit");
    }
    let parent = database
        .parent()
        .context("catalog path has no parent directory")?;
    ensure_private_parent(parent)?;
    let directory = create_recovery_directory(parent, database)?;
    let snapshot_directory = directory.join("snapshot");
    let backup_database = snapshot_directory.join(
        database
            .file_name()
            .context("catalog path has no file name")?,
    );
    let snapshot = IntegritySnapshot {
        directory,
        database: backup_database.clone(),
    };
    let snapshot_directory = snapshot
        .database
        .parent()
        .context("temporary snapshot path has no parent directory")?;
    create_private_directory(snapshot_directory)?;
    snapshot_catalog(database, &backup_database)?;
    sync_directory(snapshot_directory)?;
    sync_directory(&snapshot.directory)?;
    Ok(snapshot)
}

// Inspect a private copy so SQLite sidecar coordination cannot change the source files
fn inspect_private_snapshot(database: &Path) -> Result<super::integrity::IntegrityReport> {
    let snapshot = snapshot_for_integrity(database, true)?;
    Ok(super::integrity::inspect(snapshot.database_path()))
}

// Build and validate a backup-first recovery candidate
#[cfg(test)]
pub fn recover(
    database: &Path,
    apply: bool,
    allow_record_loss: bool,
    acknowledge_offline: bool,
) -> Result<RecoveryReport> {
    recover_with_seed_manifest(
        database,
        apply,
        allow_record_loss,
        acknowledge_offline,
        None,
    )
}

pub fn recover_with_seed_manifest(
    database: &Path,
    apply: bool,
    allow_record_loss: bool,
    acknowledge_offline: bool,
    seed_manifest_path: Option<&Path>,
) -> Result<RecoveryReport> {
    let seed_manifest = seed_manifest_path.map(load_seed_manifest).transpose()?;
    if !acknowledge_offline {
        bail!("stop every catalog writer and pass --acknowledge-offline before recovery");
    }
    if allow_record_loss && !apply {
        bail!("--allow-record-loss requires --apply");
    }
    ensure_regular_file(database)?;
    if fs::symlink_metadata(database)?.len() > MAX_SOURCE_DATABASE_BYTES {
        bail!("catalog exceeds the configured recovery input limit");
    }
    let parent = database
        .parent()
        .context("catalog path has no parent directory")?;
    ensure_private_parent(parent)?;

    let recovery_directory = create_recovery_directory(parent, database)?;
    let snapshot_directory = recovery_directory.join("snapshot");
    create_private_directory(&snapshot_directory)?;
    let backup_database = snapshot_directory.join(
        database
            .file_name()
            .context("catalog path has no file name")?,
    );
    snapshot_catalog(database, &backup_database)?;
    sync_directory(&snapshot_directory)?;
    sync_directory(&recovery_directory)?;

    let original_integrity_report = inspect_private_snapshot(&backup_database)?;
    let original_integrity = original_integrity_report.status_name();
    let original_integrity_findings = original_integrity_report.findings().to_vec();
    let original_counts = table_counts(&backup_database);
    let historical_seed_diagnostics = seed_manifest
        .as_ref()
        .map(|manifest| historical_seed_diagnostics(&backup_database, manifest))
        .transpose()?;
    let recovered_sql = recovery_directory.join("recovered.sql");
    let candidate_database = recovery_directory.join("candidate.sqlite");
    run_recover(&backup_database, &recovered_sql)?;
    import_recovered_sql(
        &recovered_sql,
        &candidate_database,
        MAX_CANDIDATE_DATABASE_BYTES,
    )?;
    ensure_candidate_bundle_size(&candidate_database, MAX_CANDIDATE_DATABASE_BYTES)?;
    set_private_file(&candidate_database)?;
    sync_file(&candidate_database)?;

    let initial_candidate_integrity = inspect_private_snapshot(&candidate_database)?;
    let expected_source = original_counts
        .get("sources")
        .copied()
        .unwrap_or(TableObservation {
            rows: RowCount::Unreadable,
            digest: None,
        });
    let (
        source_rows_reconstructed,
        source_names_disambiguated,
        source_name_types_normalized,
        source_urls_restored,
        source_rows_digest,
        mut source_reconstruction_warning,
    ) = if initial_candidate_integrity.is_healthy() {
        match restore_source_rows_from_snapshot_with_manifest(
            &backup_database,
            &candidate_database,
            expected_source,
            seed_manifest.as_ref(),
        ) {
            Ok((disambiguated, normalized, restored_urls, digest)) => (
                true,
                disambiguated,
                normalized,
                restored_urls,
                Some(digest),
                None,
            ),
            Err(error) => (
                false,
                0,
                0,
                0,
                None,
                Some(format!("source-row restoration failed: {error}")),
            ),
        }
    } else {
        (
            false,
            0,
            0,
            0,
            None,
            Some("candidate failed integrity verification before source restoration".into()),
        )
    };
    let mut provenance_rows_pruned = 0_u64;
    let mut provenance_pruning_succeeded = true;
    if source_rows_reconstructed && seed_manifest.is_some() {
        match prune_orphan_provenance(&candidate_database) {
            Ok(pruned) => provenance_rows_pruned = pruned,
            Err(error) => {
                provenance_pruning_succeeded = false;
                source_reconstruction_warning = Some(format!(
                    "source rows were restored, but orphan provenance pruning failed: {error}"
                ));
            }
        }
    }
    let mut candidate_integrity = inspect_private_snapshot(&candidate_database)?;
    let mut historical_seed_set_complete = seed_manifest.as_ref().map(|_| false);
    let application_opened_candidate = if candidate_integrity.is_healthy() {
        match mg_brief::Store::open(
            candidate_database.clone(),
            recovery_directory.join("candidate-artifacts"),
        ) {
            Ok(store) => {
                let sources_readable = match store.list_sources() {
                    Ok(sources) => {
                        let complete = seed_manifest.as_ref().is_none_or(|manifest| {
                            source_list_matches_manifest(&sources, manifest)
                        });
                        historical_seed_set_complete = seed_manifest.as_ref().map(|_| complete);
                        complete
                    }
                    Err(_) => false,
                };
                drop(store);
                checkpoint_candidate(&candidate_database)?;
                sources_readable
            }
            Err(_) => false,
        }
    } else {
        false
    };
    candidate_integrity = inspect_private_snapshot(&candidate_database)?;
    let mut foreign_key_violations = catalog_foreign_key_violations(&candidate_database).ok();
    let mut foreign_keys_valid = foreign_key_violations.as_ref().is_some_and(Vec::is_empty);
    let recovered_counts = table_counts(&candidate_database);
    let (mut counts, mut exact_records_preserved) =
        compare_counts(&original_counts, &recovered_counts);
    let no_unmapped_rows = has_no_unmapped_rows(&recovered_counts);
    let record_state_valid = record_state_matches_policy_with_manifest(
        &backup_database,
        &candidate_database,
        &original_counts,
        &recovered_counts,
        seed_manifest.as_ref(),
    )
    .unwrap_or(false);
    let approved_record_loss = !exact_records_preserved && record_state_valid;
    let candidate_valid = candidate_integrity.is_healthy()
        && application_opened_candidate
        && historical_seed_set_complete.unwrap_or(true)
        && provenance_pruning_succeeded
        && record_state_valid
        && foreign_keys_valid
        && no_unmapped_rows;

    let mut applied = false;
    let mut application_opened_installed = false;
    let mut durability_warning = None;
    let mut reported_candidate = candidate_database.clone();
    if apply
        && candidate_valid
        && (exact_records_preserved || (allow_record_loss && approved_record_loss))
    {
        let (install_warning, installed) = install_and_readback(
            database,
            &candidate_database,
            &recovery_directory,
            &backup_database,
            &snapshot_directory,
            &original_counts,
            |installed_database, directory, original| {
                read_installed_candidate_with_manifest(
                    installed_database,
                    directory,
                    original,
                    &backup_database,
                    allow_record_loss,
                    seed_manifest.as_ref(),
                )
            },
        )?;
        durability_warning = install_warning;
        application_opened_installed = installed.application_opened;
        candidate_integrity = installed.integrity;
        historical_seed_set_complete = seed_manifest
            .as_ref()
            .map(|_| installed.historical_seed_set_complete);
        foreign_keys_valid = installed.foreign_keys_valid;
        foreign_key_violations = Some(installed.foreign_key_violations);
        counts = installed.comparisons;
        exact_records_preserved = installed.exact_records_preserved;
        applied = true;
        reported_candidate = database.to_path_buf();
    }

    let record_loss_override_used = applied && !exact_records_preserved;
    let status = if applied {
        if record_loss_override_used {
            "installed_with_approved_record_loss"
        } else {
            "installed"
        }
    } else if candidate_valid && exact_records_preserved {
        "candidate_ready"
    } else if candidate_valid && approved_record_loss {
        "candidate_ready_requires_loss_override"
    } else {
        "candidate_requires_review"
    };
    Ok(RecoveryReport {
        schema: "mg.brief.recovery/1",
        status,
        recovery_directory,
        backup_database,
        candidate_database: reported_candidate,
        original_integrity,
        original_integrity_findings,
        candidate_integrity,
        foreign_keys_valid,
        foreign_key_violations,
        application_opened_candidate,
        application_opened_installed,
        exact_records_preserved,
        source_rows_reconstructed,
        source_rows_digest_sha256: source_rows_digest.map(digest_hex),
        source_snapshot_rows_digest_sha256: expected_source.digest.map(digest_hex),
        source_reconstruction_warning,
        source_names_disambiguated,
        source_name_types_normalized,
        source_urls_restored,
        historical_seed_count: seed_manifest
            .as_ref()
            .map(|manifest| manifest.sources.len()),
        historical_seed_set_complete,
        historical_seed_diagnostics,
        provenance_rows_pruned,
        record_loss_override_used,
        counts,
        applied,
        durability_warning,
    })
}

// Require every recovered row to map to a known catalog table
fn has_no_unmapped_rows(counts: &BTreeMap<&'static str, TableObservation>) -> bool {
    matches!(
        counts.get("lost_and_found"),
        Some(observation)
            if matches!(observation.rows, RowCount::Absent | RowCount::Rows(0))
    )
}

// Compare exact readable application-table records conservatively
fn compare_counts(
    original: &BTreeMap<&'static str, TableObservation>,
    recovered: &BTreeMap<&'static str, TableObservation>,
) -> (Vec<TableCountComparison>, bool) {
    let mut comparisons = Vec::with_capacity(CATALOG_TABLES.len());
    let mut preserved = true;
    for table in CATALOG_TABLES {
        let unreadable = TableObservation {
            rows: RowCount::Unreadable,
            digest: None,
        };
        let original_table = original.get(table).copied().unwrap_or(unreadable);
        let recovered_table = recovered.get(table).copied().unwrap_or(unreadable);
        let exact_records_match = match (original_table.rows, recovered_table.rows) {
            (RowCount::Absent, RowCount::Absent | RowCount::Rows(0)) => true,
            (RowCount::Rows(before), RowCount::Rows(after)) => {
                before == after
                    && original_table.digest.is_some()
                    && original_table.digest == recovered_table.digest
            }
            _ => false,
        };
        preserved &= exact_records_match;
        comparisons.push(TableCountComparison {
            table,
            original: original_table.rows,
            recovered: recovered_table.rows,
            exact_records_match,
        });
    }
    (comparisons, preserved)
}

// Accept exact records or strict row deletions from approved feed tables only
#[cfg(test)]
fn record_state_matches_policy(
    original_database: &Path,
    recovered_database: &Path,
    original: &BTreeMap<&'static str, TableObservation>,
    recovered: &BTreeMap<&'static str, TableObservation>,
) -> Result<bool> {
    record_state_matches_policy_with_manifest(
        original_database,
        recovered_database,
        original,
        recovered,
        None,
    )
}

fn record_state_matches_policy_with_manifest(
    original_database: &Path,
    recovered_database: &Path,
    original: &BTreeMap<&'static str, TableObservation>,
    recovered: &BTreeMap<&'static str, TableObservation>,
    seed_manifest: Option<&SeedManifest>,
) -> Result<bool> {
    if !has_no_unmapped_rows(recovered) {
        return Ok(false);
    }
    let original_snapshot = snapshot_for_integrity(original_database, true)?;
    let recovered_snapshot = snapshot_for_integrity(recovered_database, true)?;
    let original_snapshot_path = original_snapshot.database_path();
    let recovered_snapshot_path = recovered_snapshot.database_path();
    if !schema_objects_match(original_snapshot_path, recovered_snapshot_path)?
        || !unlisted_table_records_match(original_snapshot_path, recovered_snapshot_path)?
    {
        return Ok(false);
    }
    for table in CATALOG_TABLES {
        let before = original.get(table).copied().unwrap_or(TableObservation {
            rows: RowCount::Unreadable,
            digest: None,
        });
        let after = recovered.get(table).copied().unwrap_or(TableObservation {
            rows: RowCount::Unreadable,
            digest: None,
        });
        if matches!(before.rows, RowCount::Unreadable) || matches!(after.rows, RowCount::Unreadable)
        {
            return Ok(false);
        }
    }

    let (comparisons, exact_records_preserved) = compare_counts(original, recovered);
    if exact_records_preserved {
        return Ok(true);
    }
    let source_transform_valid = match seed_manifest {
        Some(manifest) => source_rows_match_manifest_transform(
            original_snapshot_path,
            recovered_snapshot_path,
            manifest,
        )?,
        None => false,
    };

    for comparison in comparisons {
        if comparison.exact_records_match {
            continue;
        }
        if comparison.table == "sources" && source_transform_valid {
            continue;
        }
        if !LOSS_TOLERANT_TABLES.contains(&comparison.table) {
            return Ok(false);
        }
        let (RowCount::Rows(before), RowCount::Rows(after)) =
            (comparison.original, comparison.recovered)
        else {
            return Ok(false);
        };
        if after >= before
            || !table_records_are_subset(
                original_snapshot_path,
                recovered_snapshot_path,
                comparison.table,
            )?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

// Confirm every source row matches the snapshot plus only approved seed restoration changes
fn source_rows_match_manifest_transform(
    original_database: &Path,
    recovered_database: &Path,
    manifest: &SeedManifest,
) -> Result<bool> {
    let original =
        Connection::open_with_flags(original_database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let recovered =
        Connection::open_with_flags(recovered_database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    if !schema_has_table(&original, "main", "sources")?
        || !schema_has_table(&recovered, "main", "sources")?
        || table_column_names(&original, "main", "sources")?
            != table_column_names(&recovered, "main", "sources")?
    {
        return Ok(false);
    }
    let transform = build_source_transform(&original, "main", Some(manifest))?;
    let expected = source_snapshot_with_transform(&original, "main", &transform)?;
    let actual = table_snapshot(&recovered, "sources")?;
    Ok(expected == actual)
}

// Require each historical ticker source to be enabled with its recorded interval
fn source_list_matches_manifest(sources: &[mg_brief::Source], manifest: &SeedManifest) -> bool {
    manifest.sources.iter().all(|expected| {
        sources.iter().any(|source| {
            source.name == expected.name
                && source.url == expected.url
                && source.enabled
                && source.ticker
                && source.fetch_interval_seconds == expected.every_seconds
        })
    })
}

#[derive(Debug, PartialEq, Eq)]
struct SchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: Option<String>,
}

fn schema_objects_match(original_database: &Path, recovered_database: &Path) -> Result<bool> {
    let original_connection =
        Connection::open_with_flags(original_database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let recovered_connection =
        Connection::open_with_flags(recovered_database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let original_objects = schema_objects(&original_connection)?;
    let recovered_objects = schema_objects(&recovered_connection)?;
    Ok(original_objects == recovered_objects)
}

fn schema_objects(connection: &Connection) -> Result<Vec<SchemaObject>> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name, tbl_name, sql",
    )?;
    let objects = statement
        .query_map([], |row| {
            Ok(SchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(objects)
}

fn table_names(connection: &Connection) -> Result<BTreeSet<String>> {
    let mut statement =
        connection.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?;
    let names = statement
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    Ok(names)
}

fn unlisted_table_records_match(
    original_database: &Path,
    recovered_database: &Path,
) -> Result<bool> {
    let original_connection =
        Connection::open_with_flags(original_database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let recovered_connection =
        Connection::open_with_flags(recovered_database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let original_tables = table_names(&original_connection)?;
    let recovered_tables = table_names(&recovered_connection)?;
    for table in original_tables.union(&recovered_tables) {
        if LOSS_TOLERANT_TABLES.contains(&table.as_str()) || table == "lost_and_found" {
            continue;
        }
        let original_rows = if original_tables.contains(table) {
            table_row_fingerprints(&original_connection, table)?
        } else {
            BTreeMap::new()
        };
        let recovered_rows = if recovered_tables.contains(table) {
            table_row_fingerprints(&recovered_connection, table)?
        } else {
            BTreeMap::new()
        };
        if original_rows != recovered_rows {
            return Ok(false);
        }
    }
    Ok(true)
}

fn table_records_are_subset(
    original_database: &Path,
    recovered_database: &Path,
    table: &str,
) -> Result<bool> {
    if !LOSS_TOLERANT_TABLES.contains(&table) {
        return Ok(false);
    }
    let original_connection =
        Connection::open_with_flags(original_database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let recovered_connection =
        Connection::open_with_flags(recovered_database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let original_definition = table_definition(&original_connection, table)?;
    let recovered_definition = table_definition(&recovered_connection, table)?;
    if original_definition.is_none() || original_definition != recovered_definition {
        return Ok(false);
    }
    let original_rows = table_row_fingerprints(&original_connection, table)?;
    let recovered_rows = table_row_fingerprints(&recovered_connection, table)?;
    for (fingerprint, count) in recovered_rows {
        if original_rows.get(&fingerprint).copied().unwrap_or(0) < count {
            return Ok(false);
        }
    }
    Ok(true)
}

fn table_definition(connection: &Connection, table: &str) -> Result<Option<String>> {
    Ok(connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .optional()?)
}

fn table_row_fingerprints(connection: &Connection, table: &str) -> Result<BTreeMap<[u8; 32], u64>> {
    let quoted_table = format!("\"{}\"", table.replace('"', "\"\""));
    let query = format!("SELECT * FROM {quoted_table}");
    let mut statement = connection.prepare(&query)?;
    let column_count = statement.column_count();
    let mut rows = statement.query([])?;
    let mut fingerprints = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let mut hasher = Sha256::new();
        hasher.update(b"mg-brief-recovery-row-v1\0");
        hasher.update(table.as_bytes());
        hasher.update((column_count as u64).to_be_bytes());
        for column in 0..column_count {
            match row.get_ref(column)? {
                ValueRef::Null => hasher.update([0]),
                ValueRef::Integer(value) => {
                    hasher.update([1]);
                    hasher.update(value.to_be_bytes());
                }
                ValueRef::Real(value) => {
                    hasher.update([2]);
                    hasher.update(value.to_bits().to_be_bytes());
                }
                ValueRef::Text(value) => {
                    hasher.update([3]);
                    hasher.update((value.len() as u64).to_be_bytes());
                    hasher.update(value);
                }
                ValueRef::Blob(value) => {
                    hasher.update([4]);
                    hasher.update((value.len() as u64).to_be_bytes());
                    hasher.update(value);
                }
            }
        }
        let fingerprint: [u8; 32] = hasher.finalize().into();
        let count = fingerprints.entry(fingerprint).or_insert(0_u64);
        *count = count
            .checked_add(1)
            .context("recovery row-fingerprint count overflow")?;
    }
    Ok(fingerprints)
}

// Compare complete rows from a private snapshot of fixed catalog tables
fn table_counts(database: &Path) -> BTreeMap<&'static str, TableObservation> {
    match snapshot_for_integrity(database, true) {
        Ok(snapshot) => table_counts_snapshot(snapshot.database_path()),
        Err(_) => unreadable_table_counts(),
    }
}

// Read every table from a stable private snapshot
fn table_counts_snapshot(database: &Path) -> BTreeMap<&'static str, TableObservation> {
    let mut observations = BTreeMap::new();
    let connection = match Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(connection) => connection,
        Err(_) => return unreadable_table_counts(),
    };
    for table in CATALOG_TABLES {
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get::<_, bool>(0),
        );
        let observation = match exists {
            Ok(false) => TableObservation {
                rows: RowCount::Absent,
                digest: None,
            },
            Ok(true) => match table_snapshot(&connection, table) {
                Ok((rows, digest)) => TableObservation {
                    rows: RowCount::Rows(rows),
                    digest: Some(digest),
                },
                Err(_) => TableObservation {
                    rows: RowCount::Unreadable,
                    digest: None,
                },
            },
            Err(_) => TableObservation {
                rows: RowCount::Unreadable,
                digest: None,
            },
        };
        observations.insert(*table, observation);
    }
    observations
}

// Fail closed when a private catalog snapshot cannot be read
fn unreadable_table_counts() -> BTreeMap<&'static str, TableObservation> {
    CATALOG_TABLES
        .iter()
        .map(|table| {
            (
                *table,
                TableObservation {
                    rows: RowCount::Unreadable,
                    digest: None,
                },
            )
        })
        .collect()
}

fn digest_hex(digest: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

// Hash every typed cell in rowid order without exposing catalog contents
fn table_snapshot(connection: &Connection, table: &str) -> rusqlite::Result<(i64, [u8; 32])> {
    let query = format!("SELECT * FROM \"{table}\" NOT INDEXED ORDER BY rowid");
    let mut statement = connection.prepare(&query)?;
    let column_count = statement.column_count();
    let mut rows = statement.query([])?;
    let mut hasher = Sha256::new();
    hasher.update(b"mg-brief-recovery-table-v1\0");
    hasher.update(table.as_bytes());
    hasher.update((column_count as u64).to_be_bytes());
    let mut row_count = 0_i64;
    while let Some(row) = rows.next()? {
        for column in 0..column_count {
            match row.get_ref(column)? {
                ValueRef::Null => hasher.update([0]),
                ValueRef::Integer(value) => {
                    hasher.update([1]);
                    hasher.update(value.to_be_bytes());
                }
                ValueRef::Real(value) => {
                    hasher.update([2]);
                    hasher.update(value.to_bits().to_be_bytes());
                }
                ValueRef::Text(value) => {
                    hasher.update([3]);
                    hasher.update((value.len() as u64).to_be_bytes());
                    hasher.update(value);
                }
                ValueRef::Blob(value) => {
                    hasher.update([4]);
                    hasher.update((value.len() as u64).to_be_bytes());
                    hasher.update(value);
                }
            }
        }
        hasher.update([0xff]);
        row_count += 1;
    }
    Ok((row_count, hasher.finalize().into()))
}

// Copy the live catalog and sidecars into a bounded private snapshot
fn snapshot_catalog(database: &Path, backup_database: &Path) -> Result<()> {
    snapshot_catalog_with_hook(database, backup_database, MAX_SOURCE_DATABASE_BYTES, |_| {})
}

fn snapshot_catalog_with_hook<F>(
    database: &Path,
    backup_database: &Path,
    max_bytes: u64,
    mut after_copy: F,
) -> Result<()>
where
    F: FnMut(usize),
{
    let mut sidecars = Vec::new();
    for suffix in SIDECAR_SUFFIXES {
        let source = append_suffix(database, suffix);
        if regular_file_exists(&source)? {
            sidecars.push(*suffix);
        }
    }

    let (mut total_bytes, database_version) =
        copy_private_file_bounded(database, backup_database, max_bytes)?;
    let mut copied_sources = vec![(database.to_path_buf(), database_version)];
    after_copy(0);
    for (index, suffix) in sidecars.iter().enumerate() {
        let source = append_suffix(database, suffix);
        let destination = append_suffix(backup_database, suffix);
        let remaining = max_bytes.saturating_sub(total_bytes);
        let (copied_bytes, version) = copy_private_file_bounded(&source, &destination, remaining)?;
        total_bytes = total_bytes
            .checked_add(copied_bytes)
            .context("catalog snapshot size overflow")?;
        copied_sources.push((source, version));
        after_copy(index + 1);
    }

    let mut current_sidecars = Vec::new();
    for suffix in SIDECAR_SUFFIXES {
        if regular_file_exists(&append_suffix(database, suffix))? {
            current_sidecars.push(*suffix);
        }
    }
    if current_sidecars != sidecars {
        bail!("SQLite sidecar set changed while taking the private snapshot");
    }
    for (source, expected_version) in copied_sources {
        let current_version = FileVersion::from_metadata(&fs::symlink_metadata(&source)?);
        if current_version != expected_version {
            bail!(
                "{} changed while taking the full catalog snapshot",
                source.display()
            );
        }
    }
    Ok(())
}

// Stream a stable regular file into a new private path without exceeding its byte budget
fn copy_private_file_bounded(
    source: &Path,
    destination: &Path,
    max_bytes: u64,
) -> Result<(u64, FileVersion)> {
    ensure_regular_file(source)?;
    let path_before = fs::symlink_metadata(source)?;
    if path_before.len() > max_bytes {
        bail!(
            "{} exceeds the remaining snapshot byte limit",
            source.display()
        );
    }
    let mut input = File::open(source)?;
    let input_before = input.metadata()?;
    let input_version = FileVersion::from_metadata(&input_before);
    if input_version != FileVersion::from_metadata(&path_before) {
        bail!(
            "{} changed while opening its snapshot source",
            source.display()
        );
    }

    let mut destination_created = false;
    let result = (|| -> Result<(u64, FileVersion)> {
        let mut output = create_private_file(destination)?;
        destination_created = true;
        let mut total = 0u64;
        let mut buffer = [0u8; COPY_BUFFER_BYTES];
        loop {
            let bytes_read = input.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            total = total
                .checked_add(bytes_read as u64)
                .context("catalog snapshot size overflow")?;
            if total > max_bytes {
                bail!("{} grew beyond the snapshot byte limit", source.display());
            }
            output.write_all(&buffer[..bytes_read])?;
        }
        output.sync_all()?;
        let input_after = input.metadata()?;
        let path_after = fs::symlink_metadata(source)?;
        if total != input_version.length
            || FileVersion::from_metadata(&input_after) != input_version
            || FileVersion::from_metadata(&path_after) != input_version
        {
            bail!(
                "{} changed while being copied into the snapshot",
                source.display()
            );
        }
        Ok((total, input_version))
    })();
    if result.is_err() && destination_created {
        let _ = fs::remove_file(destination);
    }
    result
}

// Copy without ever clobbering an existing recovery path
fn copy_private_file_new(source: &Path, destination: &Path) -> Result<()> {
    ensure_regular_file(source)?;
    let mut input = File::open(source)?;
    let mut output = create_private_file(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

// Create a unique recovery directory beside the catalog
fn create_recovery_directory(parent: &Path, database: &Path) -> Result<PathBuf> {
    let filename = database
        .file_name()
        .context("catalog path has no file name")?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    for attempt in 0..16u8 {
        let mut name = std::ffi::OsString::from(".");
        name.push(filename);
        name.push(format!(
            ".recovery-{nanos}-{}-{attempt}",
            std::process::id()
        ));
        let directory = parent.join(name);
        match create_private_directory(&directory) {
            Ok(()) => return Ok(directory),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("creating private recovery directory"),
        }
    }
    bail!("could not allocate a unique private recovery directory")
}

// Create a new private directory
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

// Check that the catalog parent is not writable by other users
fn ensure_private_parent(parent: &Path) -> Result<()> {
    let metadata = fs::metadata(parent)?;
    if !metadata.is_dir() {
        bail!("catalog parent is not a directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 {
            bail!("catalog parent is writable by group or other users");
        }
    }
    Ok(())
}

// Require a regular non-symlink file
fn ensure_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        bail!("catalog recovery accepts only regular files");
    }
    Ok(())
}

// Check whether a sidecar exists as a regular file
fn regular_file_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => bail!("SQLite sidecar is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

// Recover SQL from the backup using fixed system tools and the production timeout
fn run_recover(backup_database: &Path, output_path: &Path) -> Result<()> {
    run_recover_with(backup_database, output_path, SQLITE3_PATH, RECOVERY_TIMEOUT)
}

fn run_recover_with(
    backup_database: &Path,
    output_path: &Path,
    sqlite3_path: &str,
    timeout: &str,
) -> Result<()> {
    let output_file = create_private_file(output_path)?;
    let mut child = Command::new(TIMEOUT_PATH)
        .args(["--signal=TERM", "--kill-after=5s", timeout, sqlite3_path])
        .arg(backup_database)
        .arg(".recover --ignore-freelist")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("sqlite3 CLI with .recover is required for catalog recovery")?;
    let mut stdout = child
        .stdout
        .take()
        .context("sqlite3 recovery output was not available")?;
    let mut writer = output_file;
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    let mut total_bytes = 0u64;
    loop {
        let bytes_read = stdout.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        total_bytes = total_bytes
            .checked_add(bytes_read as u64)
            .context("recovery SQL size overflow")?;
        if total_bytes > MAX_RECOVERY_SQL_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            bail!("recovered SQL exceeded the configured size limit");
        }
        writer.write_all(&buffer[..bytes_read])?;
    }
    drop(stdout);
    let status = child.wait()?;
    writer.sync_all()?;
    if !status.success() {
        bail!("sqlite3 recovery exited unsuccessfully");
    }
    if total_bytes == 0 {
        bail!("sqlite3 recovery produced no SQL output");
    }
    Ok(())
}

// Import recovered SQL with SQLite enforcing the candidate page limit while it is written
fn import_recovered_sql(sql_path: &Path, candidate: &Path, max_bytes: u64) -> Result<()> {
    let page_size = recovered_page_size(sql_path)?;
    let max_pages = max_bytes / u64::from(page_size);
    if max_pages == 0 {
        bail!("candidate byte limit is smaller than the recovered SQLite page size");
    }
    let mut input = File::open(sql_path)?;
    // Recovered SQL can change max_page_count; RLIMIT_FSIZE remains a kernel-enforced ceiling.
    let file_limit = format!("--fsize={max_bytes}:{max_bytes}");
    let mut child = Command::new(PRLIMIT_PATH)
        .arg("--core=0:0")
        .arg(file_limit)
        .arg("--")
        .arg(TIMEOUT_PATH)
        .args([
            "--signal=TERM",
            "--kill-after=5s",
            RECOVERY_TIMEOUT,
            SQLITE3_PATH,
            "--safe",
            "-bail",
        ])
        .arg(candidate)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("sqlite3 CLI is required to import the recovery candidate")?;
    let mut sqlite_stdin = child
        .stdin
        .take()
        .context("sqlite3 candidate input was not available")?;
    let preamble = format!("PRAGMA page_size={page_size};\nPRAGMA max_page_count={max_pages};\n");
    let copy_result = (|| -> Result<()> {
        sqlite_stdin.write_all(preamble.as_bytes())?;
        std::io::copy(&mut input, &mut sqlite_stdin)?;
        Ok(())
    })();
    drop(sqlite_stdin);
    let status = child.wait()?;
    copy_result.context("streaming bounded recovery SQL into sqlite3")?;
    if !status.success() {
        bail!("sqlite3 rejected the recovered SQL or reached the candidate size limit");
    }
    let candidate_bytes = fs::metadata(candidate)?.len();
    if candidate_bytes > max_bytes {
        bail!("recovery candidate exceeded the configured size limit");
    }
    Ok(())
}

// Reject candidate bundles whose main database and SQLite sidecars exceed the bundle limit
fn ensure_candidate_bundle_size(candidate: &Path, max_bytes: u64) -> Result<()> {
    ensure_regular_file(candidate)?;
    let mut total = fs::symlink_metadata(candidate)?.len();
    if total > max_bytes {
        bail!("recovery candidate exceeds the configured bundle limit");
    }
    for suffix in SIDECAR_SUFFIXES {
        let sidecar = append_suffix(candidate, suffix);
        if regular_file_exists(&sidecar)? {
            total = total
                .checked_add(fs::symlink_metadata(&sidecar)?.len())
                .context("candidate bundle size overflow")?;
            if total > max_bytes {
                bail!("recovery candidate and SQLite sidecars exceed the bundle limit");
            }
        }
    }
    Ok(())
}

// Parse SQLite's bounded recovery header before importing any recovered rows
fn recovered_page_size(sql_path: &Path) -> Result<u32> {
    let mut prefix = String::new();
    BufReader::new(File::open(sql_path)?)
        .take(4096)
        .read_to_string(&mut prefix)?;
    for line in prefix.lines().take(32) {
        let Some(value) = line
            .trim_end_matches('\r')
            .strip_prefix("PRAGMA page_size = '")
            .and_then(|value| value.strip_suffix("';"))
        else {
            continue;
        };
        let page_size = value
            .parse::<u32>()
            .context("recovery SQL contains an invalid SQLite page size")?;
        if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
            bail!("recovery SQL declares an unsupported SQLite page size");
        }
        return Ok(page_size);
    }
    bail!("recovery SQL did not declare a supported SQLite page size")
}

// Check SQLite's application-managed candidate with the normal store opener
fn checkpoint_candidate(candidate: &Path) -> Result<()> {
    let connection = Connection::open(candidate)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    let mode: String = connection.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("delete") {
        bail!("candidate could not leave WAL mode before installation");
    }
    drop(connection);
    for suffix in SIDECAR_SUFFIXES {
        let sidecar = append_suffix(candidate, suffix);
        if regular_file_exists(&sidecar)? {
            fs::remove_file(sidecar)?;
        }
    }
    sync_file(candidate)?;
    Ok(())
}

// Restore source configuration rows from the private original snapshot into the candidate
#[cfg(test)]
fn restore_source_rows_from_snapshot(
    original_database: &Path,
    candidate: &Path,
    expected_source: TableObservation,
) -> Result<()> {
    restore_source_rows_from_snapshot_with_manifest(
        original_database,
        candidate,
        expected_source,
        None,
    )
    .map(|_| ())
}

fn restore_source_rows_from_snapshot_with_manifest(
    original_database: &Path,
    candidate: &Path,
    expected_source: TableObservation,
    seed_manifest: Option<&SeedManifest>,
) -> Result<(usize, usize, usize, [u8; 32])> {
    let (expected_rows, expected_digest) = match (expected_source.rows, expected_source.digest) {
        (RowCount::Rows(rows), Some(digest)) => (rows, digest),
        _ => bail!("original source rows were not fully readable for reseeding"),
    };
    let source_snapshot = snapshot_for_integrity(original_database, true)?;
    let source_connection = Connection::open_with_flags(
        source_snapshot.database_path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (snapshot_rows, snapshot_digest) = table_snapshot(&source_connection, "sources")?;
    if snapshot_rows != expected_rows || snapshot_digest != expected_digest {
        bail!("private source snapshot did not match the expected source-row digest");
    }
    let mut source_uri = Url::from_file_path(source_snapshot.database_path())
        .map_err(|_| anyhow::anyhow!("could not form a private source snapshot URI"))?;
    source_uri.query_pairs_mut().append_pair("mode", "ro");

    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI;
    let mut candidate_connection = Connection::open_with_flags(candidate, flags)?;
    let journal_mode: String =
        candidate_connection.query_row("PRAGMA journal_mode=MEMORY", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("memory") {
        bail!("candidate could not use a private in-memory rollback journal");
    }
    let page_size: i64 =
        candidate_connection.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    if page_size <= 0 {
        bail!("candidate has an invalid SQLite page size");
    }
    let max_pages = MAX_CANDIDATE_DATABASE_BYTES / page_size as u64;
    candidate_connection.pragma_update(
        None,
        "max_page_count",
        i64::try_from(max_pages).context("candidate page limit exceeds SQLite integer range")?,
    )?;
    candidate_connection.execute_batch("PRAGMA foreign_keys=OFF;")?;
    candidate_connection.execute(
        "ATTACH DATABASE ?1 AS recovery_source",
        [source_uri.as_str()],
    )?;

    if !schema_has_table(&candidate_connection, "recovery_source", "sources")?
        || !schema_has_table(&candidate_connection, "main", "sources")?
    {
        bail!("source table is missing from the original snapshot or recovery candidate");
    }
    let original_columns = table_column_names(&candidate_connection, "recovery_source", "sources")?;
    let candidate_columns = table_column_names(&candidate_connection, "main", "sources")?;
    if original_columns != candidate_columns {
        bail!("source table schema differs between the original snapshot and candidate");
    }
    let source_unique_indexes =
        source_unique_index_summaries(&candidate_connection, &source_connection)?;
    if source_unique_indexes
        .iter()
        .any(|index| index.duplicate_groups.is_none())
    {
        bail!("source unique-index forms are not supported for safe reseeding");
    }
    let duplicate_index_conflict = source_unique_indexes.iter().any(|index| {
        index.duplicate_groups.is_some_and(|groups| groups > 0)
            && !(index.key_columns == ["name"] && index.key_collations == ["BINARY"])
    });
    if duplicate_index_conflict {
        bail!(
            "private source rows conflict with a non-name unique index: {}",
            format_source_unique_indexes(&source_unique_indexes)
        );
    }
    let transform = build_source_transform(&source_connection, "main", seed_manifest)?;
    if transform.disambiguated_names > 0 && seed_manifest.is_none() {
        bail!(
            "duplicate source names require an authoritative seed manifest: {}",
            format_source_unique_indexes(&source_unique_indexes)
        );
    }
    let expected_transformed =
        source_snapshot_with_transform(&source_connection, "main", &transform)?;
    if expected_transformed.0 != expected_rows {
        bail!("source transform changed the original source-row count");
    }

    let transaction =
        candidate_connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TEMP TABLE source_overrides (id INTEGER PRIMARY KEY, name TEXT, url TEXT, enabled INTEGER, ticker INTEGER, fetch_interval_seconds INTEGER);",
    )?;
    {
        let mut insert_override = transaction.prepare(
            "INSERT INTO temp.source_overrides (id, name, url, enabled, ticker, fetch_interval_seconds) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for (id, override_row) in &transform.overrides {
            insert_override.execute(rusqlite::params![
                id,
                override_row.name,
                override_row.url,
                override_row.enabled,
                override_row.ticker,
                override_row.fetch_interval_seconds,
            ])?;
        }
    }
    let columns = candidate_columns
        .iter()
        .map(|column| quote_identifier(column))
        .collect::<Vec<_>>()
        .join(", ");
    let selected_columns = candidate_columns
        .iter()
        .map(|column| match column.as_str() {
            "name" => "COALESCE(o.name, src.\"name\")".to_owned(),
            "url" => "COALESCE(o.url, src.\"url\")".to_owned(),
            "enabled" => "COALESCE(o.enabled, src.\"enabled\")".to_owned(),
            "ticker" => "COALESCE(o.ticker, src.\"ticker\")".to_owned(),
            "fetch_interval_seconds" => {
                "COALESCE(o.fetch_interval_seconds, src.\"fetch_interval_seconds\")".to_owned()
            }
            _ => format!("src.{}", quote_identifier(column)),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let copy_sql = format!(
        "DELETE FROM main.sources; INSERT INTO main.sources ({columns}) SELECT {selected_columns} FROM recovery_source.sources AS src NOT INDEXED LEFT JOIN temp.source_overrides AS o ON o.id = src.id ORDER BY src.rowid;"
    );
    let copy_result = transaction.execute_batch(&copy_sql);
    if let Err(error) = copy_result {
        drop(transaction);
        let source_unique_indexes =
            source_unique_index_summaries(&candidate_connection, &source_connection)?;
        let candidate_unique_indexes =
            source_unique_index_summaries(&candidate_connection, &candidate_connection)?;
        bail!(
            "source-row transaction rolled back ({error}); private source unique indexes: {}; recovered candidate unique indexes: {}",
            format_source_unique_indexes(&source_unique_indexes),
            format_source_unique_indexes(&candidate_unique_indexes)
        );
    }
    let (copied_rows, copied_digest) = table_snapshot(&transaction, "sources")?;
    if copied_rows != expected_transformed.0 || copied_digest != expected_transformed.1 {
        bail!("restored source rows did not match the validated source transform");
    }
    let copied_unique_indexes = source_unique_index_summaries(&transaction, &transaction)?;
    if copied_unique_indexes
        .iter()
        .any(|index| index.duplicate_groups != Some(0))
    {
        bail!("restored source rows still violate a unique index");
    }
    // Validate before commit so every fallible reseed check can still roll back
    transaction.commit()?;
    drop(source_connection);
    drop(candidate_connection);
    Ok((
        transform.disambiguated_names,
        transform.normalized_name_types,
        transform.restored_urls,
        copied_digest,
    ))
}

// Read only the fields needed to bind historical feeds and resolve name collisions
fn read_source_identities(connection: &Connection, schema: &str) -> Result<Vec<SourceIdentity>> {
    let query = format!("SELECT id, name, url FROM {schema}.sources NOT INDEXED ORDER BY id");
    let mut statement = connection.prepare(&query)?;
    let mut rows = statement.query([])?;
    let mut identities = Vec::new();
    while let Some(row) = rows.next()? {
        let (name, name_was_integer) = match row.get_ref(1)? {
            ValueRef::Text(value) => (std::str::from_utf8(value)?.to_owned(), false),
            ValueRef::Integer(value) => (value.to_string(), true),
            _ => bail!("private source snapshot has an unsupported source-name storage type"),
        };
        identities.push(SourceIdentity {
            id: row.get(0)?,
            name,
            name_was_integer,
            url: row.get(2)?,
        });
    }
    Ok(identities)
}

// Resolve a missing historical source row only through its own recorded provenance URL
fn provenance_source_ids(connection: &Connection, schema: &str, url: &str) -> Result<Vec<i64>> {
    if !schema_has_table(connection, schema, "fetch_runs")?
        || !schema_has_table(connection, schema, "provenance")?
    {
        return Ok(Vec::new());
    }
    let query = format!(
        "SELECT fr.source_id FROM {schema}.fetch_runs AS fr JOIN {schema}.provenance AS p ON p.fetch_run_id = fr.id WHERE p.source_url = ?1 GROUP BY fr.source_id ORDER BY fr.source_id"
    );
    let mut statement = connection.prepare(&query)?;
    let ids = statement
        .query_map([url], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<i64>>>()?;
    Ok(ids)
}

// Produce a redacted, row-count-only map from historical feeds to saved source IDs
fn historical_seed_diagnostics(
    database: &Path,
    manifest: &SeedManifest,
) -> Result<Vec<HistoricalSeedDiagnostic>> {
    let connection = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let has_sources = schema_has_table(&connection, "main", "sources")?;
    let has_fetch_runs = schema_has_table(&connection, "main", "fetch_runs")?;
    let has_feed_items = schema_has_table(&connection, "main", "feed_items")?;
    let mut diagnostics = Vec::with_capacity(manifest.sources.len());

    for expected in &manifest.sources {
        let mut source_ids = BTreeSet::new();
        if has_sources {
            for query in [
                "SELECT id FROM sources NOT INDEXED WHERE url = ?1",
                "SELECT id FROM sources NOT INDEXED WHERE name = ?1",
            ] {
                let mut statement = connection.prepare(query)?;
                let values = statement
                    .query_map(
                        [if query.contains("url =") {
                            expected.url.as_str()
                        } else {
                            expected.name.as_str()
                        }],
                        |row| row.get::<_, i64>(0),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                source_ids.extend(values);
            }
        }
        source_ids.extend(provenance_source_ids(&connection, "main", &expected.url)?);

        let mut references = Vec::with_capacity(source_ids.len());
        for source_id in source_ids {
            let (source_row_present, historical_name_matches, historical_url_matches) =
                if has_sources {
                    connection.query_row(
                        "SELECT EXISTS(SELECT 1 FROM sources WHERE id = ?1), EXISTS(SELECT 1 FROM sources WHERE id = ?1 AND name = ?2), EXISTS(SELECT 1 FROM sources WHERE id = ?1 AND url = ?3)",
                        rusqlite::params![source_id, expected.name, expected.url],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )?
                } else {
                    (false, false, false)
                };
            let fetch_runs = if has_fetch_runs {
                count_child_rows(&connection, "fetch_runs", source_id)?
            } else {
                0
            };
            let feed_items = if has_feed_items {
                count_child_rows(&connection, "feed_items", source_id)?
            } else {
                0
            };
            let provenance_rows = if has_fetch_runs
                && schema_has_table(&connection, "main", "provenance")?
            {
                let count: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM fetch_runs AS fr JOIN provenance AS p ON p.fetch_run_id = fr.id WHERE fr.source_id = ?1 AND p.source_url = ?2",
                    rusqlite::params![source_id, expected.url],
                    |row| row.get(0),
                )?;
                u64::try_from(count).context("historical provenance reference count is invalid")?
            } else {
                0
            };
            references.push(HistoricalSeedSourceIdDiagnostic {
                source_id,
                source_row_present,
                historical_name_matches,
                historical_url_matches,
                fetch_runs,
                feed_items,
                provenance_rows,
            });
        }
        diagnostics.push(HistoricalSeedDiagnostic {
            name: expected.name.clone(),
            source_ids: references,
        });
    }
    Ok(diagnostics)
}

// Count child rows without returning any source, item, or URL fields
fn count_child_rows(connection: &Connection, table: &str, source_id: i64) -> Result<u64> {
    let query = match table {
        "fetch_runs" => "SELECT COUNT(*) FROM fetch_runs WHERE source_id = ?1",
        "feed_items" => "SELECT COUNT(*) FROM feed_items WHERE source_id = ?1",
        _ => bail!("unsupported source child table for diagnostics"),
    };
    let count: i64 = connection.query_row(query, [source_id], |row| row.get(0))?;
    u64::try_from(count).context("historical source child row count is invalid")
}

// Derive the only permitted source changes from the authoritative seed set
fn build_source_transform(
    connection: &Connection,
    schema: &str,
    seed_manifest: Option<&SeedManifest>,
) -> Result<SourceTransform> {
    let identities = read_source_identities(connection, schema)?;
    let normalized_name_types = identities
        .iter()
        .filter(|source| source.name_was_integer)
        .count();
    if normalized_name_types > 0 && seed_manifest.is_none() {
        bail!("integer source names require an authoritative seed manifest for text normalization");
    }
    let mut transform = SourceTransform {
        normalized_name_types,
        ..SourceTransform::default()
    };
    let mut desired_names = identities
        .iter()
        .map(|source| (source.id, source.name.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut seed_ids = BTreeSet::new();
    for source in identities.iter().filter(|source| source.name_was_integer) {
        transform.overrides.insert(
            source.id,
            SourceOverride {
                name: Some(source.name.clone()),
                ..SourceOverride::default()
            },
        );
    }

    if let Some(manifest) = seed_manifest {
        let mut by_url = BTreeMap::new();
        let by_id = identities
            .iter()
            .map(|source| (source.id, source))
            .collect::<BTreeMap<_, _>>();
        for source in &identities {
            if by_url.insert(source.url.as_str(), source).is_some() {
                bail!("private source snapshot contains duplicate URLs");
            }
        }
        for expected in &manifest.sources {
            let source = if let Some(source) = by_url.get(expected.url.as_str()) {
                *source
            } else {
                let referenced_ids = provenance_source_ids(connection, schema, &expected.url)?;
                match referenced_ids.as_slice() {
                    [source_id] => by_id.get(source_id).with_context(|| {
                        format!(
                            "historical source '{}' has no existing source row at its provenance id",
                            expected.name
                        )
                    })?,
                    [] => {
                        let name_matches = identities
                            .iter()
                            .filter(|source| source.name == expected.name)
                            .collect::<Vec<_>>();
                        if name_matches.len() != 1 {
                            bail!(
                                "historical source '{}' is not present by URL and has no unique name or provenance match",
                                expected.name
                            );
                        }
                        name_matches[0]
                    }
                    _ => {
                        bail!(
                            "historical source '{}' has provenance tied to multiple source ids",
                            expected.name
                        );
                    }
                }
            };
            if seed_ids.contains(&source.id) {
                bail!("historical seed manifest resolves multiple feeds to the same source id");
            }
            if by_url.contains_key(expected.url.as_str()) {
                let referenced_ids = provenance_source_ids(connection, schema, &expected.url)?;
                if referenced_ids
                    .iter()
                    .any(|source_id| *source_id != source.id)
                {
                    bail!(
                        "historical source '{}' has provenance tied to conflicting source ids",
                        expected.name
                    );
                }
            } else {
                transform.restored_urls = transform
                    .restored_urls
                    .checked_add(1)
                    .context("source URL restoration count overflow")?;
            }
            desired_names.insert(source.id, expected.name.clone());
            seed_ids.insert(source.id);
            transform.overrides.insert(
                source.id,
                SourceOverride {
                    name: Some(expected.name.clone()),
                    url: Some(expected.url.clone()),
                    enabled: Some(1),
                    ticker: Some(1),
                    fetch_interval_seconds: Some(expected.every_seconds),
                },
            );
        }
    }

    let mut names_to_ids = BTreeMap::<String, Vec<i64>>::new();
    for (id, name) in &desired_names {
        names_to_ids.entry(name.clone()).or_default().push(*id);
    }
    for (name, ids) in names_to_ids.into_iter().filter(|(_, ids)| ids.len() > 1) {
        let keeper = ids
            .iter()
            .copied()
            .find(|id| seed_ids.contains(id))
            .or_else(|| ids.iter().min().copied())
            .context("duplicate source group is unexpectedly empty")?;
        for id in ids.into_iter().filter(|id| *id != keeper) {
            let alias = format!("{name} [source-id:{id}]");
            if alias.len() > 512 {
                bail!("duplicate source name is too long to disambiguate safely");
            }
            desired_names.insert(id, alias.clone());
            transform.overrides.entry(id).or_default().name = Some(alias);
            transform.disambiguated_names = transform
                .disambiguated_names
                .checked_add(1)
                .context("source name disambiguation count overflow")?;
        }
    }
    let unique_names = desired_names.values().collect::<BTreeSet<_>>();
    if unique_names.len() != desired_names.len() {
        bail!("deterministic source-name suffixes did not produce unique names");
    }
    Ok(transform)
}

// Hash the source snapshot after the exact approved field transform
fn source_snapshot_with_transform(
    connection: &Connection,
    schema: &str,
    transform: &SourceTransform,
) -> Result<(i64, [u8; 32])> {
    let column_names = table_column_names(connection, schema, "sources")?;
    let id_index = column_names
        .iter()
        .position(|column| column == "id")
        .context("source table has no id column")?;
    let query = format!("SELECT * FROM {schema}.sources NOT INDEXED ORDER BY rowid");
    let mut statement = connection.prepare(&query)?;
    let mut rows = statement.query([])?;
    let mut hasher = Sha256::new();
    hasher.update(b"mg-brief-recovery-table-v1\0");
    hasher.update(b"sources");
    hasher.update((column_names.len() as u64).to_be_bytes());
    let mut row_count = 0_i64;
    while let Some(row) = rows.next()? {
        let id = row.get::<_, i64>(id_index)?;
        let override_row = transform.overrides.get(&id);
        for (index, column) in column_names.iter().enumerate() {
            let override_value = override_row.and_then(|item| match column.as_str() {
                "name" => item
                    .name
                    .as_ref()
                    .map(|value| SourceCellOverride::Text(value)),
                "url" => item
                    .url
                    .as_ref()
                    .map(|value| SourceCellOverride::Text(value)),
                "enabled" => item.enabled.map(SourceCellOverride::Integer),
                "ticker" => item.ticker.map(SourceCellOverride::Integer),
                "fetch_interval_seconds" => {
                    item.fetch_interval_seconds.map(SourceCellOverride::Integer)
                }
                _ => None,
            });
            if let Some(value) = override_value {
                match value {
                    SourceCellOverride::Text(value) => {
                        hash_text_cell(&mut hasher, value.as_bytes())
                    }
                    SourceCellOverride::Integer(value) => hash_integer_cell(&mut hasher, value),
                }
            } else {
                hash_sqlite_cell(&mut hasher, row.get_ref(index)?);
            }
        }
        hasher.update([0xff]);
        row_count = row_count
            .checked_add(1)
            .context("source row count overflow")?;
    }
    Ok((row_count, hasher.finalize().into()))
}

enum SourceCellOverride<'a> {
    Text(&'a str),
    Integer(i64),
}

fn hash_sqlite_cell(hasher: &mut Sha256, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => hasher.update([0]),
        ValueRef::Integer(value) => hash_integer_cell(hasher, value),
        ValueRef::Real(value) => {
            hasher.update([2]);
            hasher.update(value.to_bits().to_be_bytes());
        }
        ValueRef::Text(value) => hash_text_cell(hasher, value),
        ValueRef::Blob(value) => {
            hasher.update([4]);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
    }
}

fn hash_text_cell(hasher: &mut Sha256, value: &[u8]) {
    hasher.update([3]);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hash_integer_cell(hasher: &mut Sha256, value: i64) {
    hasher.update([1]);
    hasher.update(value.to_be_bytes());
}

// Remove only provenance records whose exact referenced parent row was not recovered
fn prune_orphan_provenance(candidate: &Path) -> Result<u64> {
    let mut connection = Connection::open(candidate)?;
    connection.execute_batch("PRAGMA foreign_keys=ON;")?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let deleted = transaction.execute(
        "DELETE FROM provenance WHERE NOT EXISTS (SELECT 1 FROM fetch_runs WHERE fetch_runs.id = provenance.fetch_run_id) OR NOT EXISTS (SELECT 1 FROM artifacts WHERE artifacts.id = provenance.artifact_id) OR (provenance.item_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM feed_items WHERE feed_items.id = provenance.item_id))",
        [],
    )?;
    transaction.commit()?;
    Ok(deleted as u64)
}

fn source_unique_index_summaries(
    index_connection: &Connection,
    rows_connection: &Connection,
) -> Result<Vec<SourceUniqueIndexSummary>> {
    let mut statement = index_connection.prepare("PRAGMA main.index_list('sources')")?;
    let indexes = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, bool>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut summaries = Vec::new();
    for (index_name, unique, partial) in indexes {
        if !unique {
            continue;
        }
        let index_literal = format!("'{}'", index_name.replace('\'', "''"));
        let query = format!("PRAGMA main.index_xinfo({index_literal})");
        let mut info = index_connection.prepare(&query)?;
        let key_parts = info
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut key_columns = Vec::new();
        let mut key_collations = Vec::new();
        let mut supported = !partial;
        for (column_id, name, collation, is_key) in key_parts {
            if !is_key {
                continue;
            }
            let (Some(name), Some(collation)) = (name, collation) else {
                supported = false;
                continue;
            };
            let collation = collation.to_ascii_uppercase();
            if column_id < 0 || !matches!(collation.as_str(), "BINARY" | "NOCASE" | "RTRIM") {
                supported = false;
                continue;
            }
            key_columns.push(name);
            key_collations.push(collation);
        }
        let duplicate_groups = if !supported || key_columns.is_empty() {
            None
        } else {
            let expressions = key_columns
                .iter()
                .zip(&key_collations)
                .map(|(column, collation)| {
                    format!("{} COLLATE {collation}", quote_identifier(column))
                })
                .collect::<Vec<_>>()
                .join(", ");
            let duplicate_query = format!(
                "SELECT COUNT(*) FROM (SELECT 1 FROM sources NOT INDEXED GROUP BY {expressions} HAVING COUNT(*) > 1)"
            );
            Some(rows_connection.query_row(&duplicate_query, [], |row| row.get(0))?)
        };
        summaries.push(SourceUniqueIndexSummary {
            index_name,
            key_columns,
            key_collations,
            duplicate_groups,
        });
    }
    Ok(summaries)
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn format_source_unique_indexes(indexes: &[SourceUniqueIndexSummary]) -> String {
    indexes
        .iter()
        .map(|index| {
            format!(
                "{} columns={:?} collations={:?} duplicate_groups={:?}",
                index.index_name, index.key_columns, index.key_collations, index.duplicate_groups
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn schema_has_table(connection: &Connection, schema: &str, table: &str) -> Result<bool> {
    let query = format!(
        "SELECT EXISTS(SELECT 1 FROM {schema}.sqlite_master WHERE type='table' AND name=?1)"
    );
    Ok(connection.query_row(&query, [table], |row| row.get(0))?)
}

fn table_column_names(connection: &Connection, schema: &str, table: &str) -> Result<Vec<String>> {
    let query = format!("PRAGMA {schema}.table_info(\"{table}\")");
    let mut statement = connection.prepare(&query)?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names)
}

// Install a validated candidate while retaining the original and sidecars in the recovery directory
fn install_candidate(
    database: &Path,
    candidate: &Path,
    recovery_directory: &Path,
    backup_database: &Path,
) -> Result<Option<String>> {
    if !catalog_bundle_matches_snapshot(database, backup_database)? {
        bail!("live catalog or SQLite sidecars changed after the recovery snapshot");
    }
    let mut live_sidecars = Vec::new();
    for suffix in SIDECAR_SUFFIXES {
        let live_sidecar = append_suffix(database, suffix);
        if regular_file_exists(&live_sidecar)? {
            live_sidecars.push(live_sidecar);
        }
    }

    let mut moved_sidecars = Vec::new();
    for (index, live_sidecar) in live_sidecars.iter().enumerate() {
        let archived_sidecar = recovery_directory.join(format!("active-sidecar-{index}"));
        if let Err(error) = fs::rename(live_sidecar, &archived_sidecar) {
            return Err(installation_error(
                error,
                &moved_sidecars,
                recovery_directory,
                "quiescing catalog sidecars before installation",
            ));
        }
        moved_sidecars.push((live_sidecar.clone(), archived_sidecar));
    }
    let quiesced_matches =
        match quiesced_catalog_matches_snapshot(database, backup_database, &moved_sidecars) {
            Ok(matches) => matches,
            Err(error) => {
                return Err(installation_error(
                    std::io::Error::other(error.to_string()),
                    &moved_sidecars,
                    recovery_directory,
                    "revalidating the catalog before installation",
                ));
            }
        };
    if !quiesced_matches {
        return Err(installation_error(
            std::io::Error::other("catalog changed after the recovery snapshot"),
            &moved_sidecars,
            recovery_directory,
            "revalidating the catalog before installation",
        ));
    }
    if let Err(error) = fs::rename(candidate, database) {
        return Err(installation_error(
            error,
            &moved_sidecars,
            recovery_directory,
            "atomically installing the recovered catalog",
        ));
    }
    match database.parent().map(sync_directory).transpose() {
        Ok(_) => Ok(None),
        Err(error) => Ok(Some(format!(
            "catalog was installed, but parent-directory sync failed: {error}"
        ))),
    }
}

fn catalog_bundle_matches_snapshot(database: &Path, snapshot: &Path) -> Result<bool> {
    let mut total_bytes = 0_u64;
    let mut pairs = vec![(database.to_path_buf(), snapshot.to_path_buf())];
    for suffix in SIDECAR_SUFFIXES {
        pairs.push((
            append_suffix(database, suffix),
            append_suffix(snapshot, suffix),
        ));
    }
    for (live, expected) in pairs {
        let live_exists = regular_file_exists(&live)?;
        let expected_exists = regular_file_exists(&expected)?;
        if live_exists != expected_exists {
            return Ok(false);
        }
        if !live_exists {
            continue;
        }
        let (live_digest, live_length) = stable_file_digest(&live)?;
        let (expected_digest, expected_length) = stable_file_digest(&expected)?;
        total_bytes = total_bytes
            .checked_add(live_length)
            .context("catalog bundle size overflow")?;
        if total_bytes > MAX_SOURCE_DATABASE_BYTES
            || live_length != expected_length
            || live_digest != expected_digest
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn quiesced_catalog_matches_snapshot(
    database: &Path,
    snapshot: &Path,
    moved_sidecars: &[(PathBuf, PathBuf)],
) -> Result<bool> {
    let (live_digest, live_length) = stable_file_digest(database)?;
    let (snapshot_digest, snapshot_length) = stable_file_digest(snapshot)?;
    if live_length != snapshot_length || live_digest != snapshot_digest {
        return Ok(false);
    }
    for suffix in SIDECAR_SUFFIXES {
        let live_sidecar = append_suffix(database, suffix);
        if regular_file_exists(&live_sidecar)? {
            return Ok(false);
        }
        let snapshot_sidecar = append_suffix(snapshot, suffix);
        let expected_exists = regular_file_exists(&snapshot_sidecar)?;
        let archived = moved_sidecars
            .iter()
            .find(|(live, _)| *live == live_sidecar)
            .map(|(_, archived)| archived);
        if expected_exists != archived.is_some() {
            return Ok(false);
        }
        if let Some(archived) = archived {
            let (archived_digest, archived_length) = stable_file_digest(archived)?;
            let (snapshot_digest, snapshot_length) = stable_file_digest(&snapshot_sidecar)?;
            if archived_length != snapshot_length || archived_digest != snapshot_digest {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn stable_file_digest(path: &Path) -> Result<([u8; 32], u64)> {
    ensure_regular_file(path)?;
    let path_before = fs::symlink_metadata(path)?;
    if path_before.len() > MAX_SOURCE_DATABASE_BYTES {
        bail!("catalog bundle member exceeds the configured size limit");
    }
    let mut file = File::open(path)?;
    let file_before = FileVersion::from_metadata(&file.metadata()?);
    if file_before != FileVersion::from_metadata(&path_before) {
        bail!("catalog bundle member changed while opening it");
    }
    let mut hasher = Sha256::new();
    let mut total_bytes = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes
            .checked_add(read as u64)
            .context("catalog bundle size overflow")?;
        if total_bytes > MAX_SOURCE_DATABASE_BYTES {
            bail!("catalog bundle member exceeds the configured size limit");
        }
        hasher.update(&buffer[..read]);
    }
    let file_after = FileVersion::from_metadata(&file.metadata()?);
    let path_after = FileVersion::from_metadata(&fs::symlink_metadata(path)?);
    if total_bytes != file_before.length || file_after != file_before || path_after != file_before {
        bail!("catalog bundle member changed while hashing it");
    }
    Ok((hasher.finalize().into(), total_bytes))
}

#[cfg(test)]
fn read_installed_candidate(
    database: &Path,
    recovery_directory: &Path,
    original_counts: &BTreeMap<&'static str, TableObservation>,
    original_database: &Path,
    allow_record_loss: bool,
) -> Result<InstalledReadback> {
    read_installed_candidate_with_manifest(
        database,
        recovery_directory,
        original_counts,
        original_database,
        allow_record_loss,
        None,
    )
}

fn read_installed_candidate_with_manifest(
    database: &Path,
    recovery_directory: &Path,
    original_counts: &BTreeMap<&'static str, TableObservation>,
    original_database: &Path,
    allow_record_loss: bool,
    seed_manifest: Option<&SeedManifest>,
) -> Result<InstalledReadback> {
    let mut historical_seed_set_complete = seed_manifest.is_none();
    let application_opened = match mg_brief::Store::open(
        database.to_path_buf(),
        recovery_directory.join("installed-artifacts"),
    ) {
        Ok(store) => {
            let sources_readable = match store.list_sources() {
                Ok(sources) => {
                    historical_seed_set_complete = seed_manifest
                        .is_none_or(|manifest| source_list_matches_manifest(&sources, manifest));
                    historical_seed_set_complete
                }
                Err(_) => false,
            };
            drop(store);
            sources_readable
        }
        Err(_) => false,
    };
    let integrity = inspect_private_snapshot(database)?;
    let installed_counts = table_counts(database);
    let (comparisons, exact_records_preserved) = compare_counts(original_counts, &installed_counts);
    let source_rows_exact = comparisons
        .iter()
        .find(|comparison| comparison.table == "sources")
        .is_some_and(|comparison| comparison.exact_records_match);
    let record_state_valid = record_state_matches_policy_with_manifest(
        original_database,
        database,
        original_counts,
        &installed_counts,
        seed_manifest,
    )?;
    let source_rows_normalized = match seed_manifest {
        Some(manifest) => {
            source_rows_match_manifest_transform(original_database, database, manifest)?
        }
        None => false,
    };
    let source_rows_accepted = source_rows_exact
        || source_rows_normalized
        || (allow_record_loss
            && record_state_valid
            && source_rows_strictly_reduced(original_counts, &installed_counts));
    let foreign_key_violations = catalog_foreign_key_violations(database)?;
    let foreign_keys_valid = foreign_key_violations.is_empty();
    let approved_record_loss = allow_record_loss && !exact_records_preserved && record_state_valid;
    Ok(InstalledReadback {
        application_opened,
        integrity,
        comparisons,
        exact_records_preserved,
        record_state_valid,
        approved_record_loss,
        source_rows_accepted,
        historical_seed_set_complete,
        foreign_keys_valid,
        foreign_key_violations,
        no_unmapped_rows: has_no_unmapped_rows(&installed_counts),
    })
}

fn source_rows_strictly_reduced(
    original: &BTreeMap<&'static str, TableObservation>,
    recovered: &BTreeMap<&'static str, TableObservation>,
) -> bool {
    matches!(
        (
            original.get("sources").map(|observation| observation.rows),
            recovered.get("sources").map(|observation| observation.rows),
        ),
        (Some(RowCount::Rows(before)), Some(RowCount::Rows(after))) if after < before
    )
}

#[cfg(test)]
fn catalog_foreign_keys_valid(database: &Path) -> Result<bool> {
    Ok(catalog_foreign_key_violations(database)?.is_empty())
}

fn catalog_foreign_key_violations(database: &Path) -> Result<Vec<ForeignKeyViolationSummary>> {
    let snapshot = snapshot_for_integrity(database, true)?;
    let connection =
        Connection::open_with_flags(snapshot.database_path(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    let mut groups = BTreeMap::<(String, String), u64>::new();
    while let Some(row) = rows.next()? {
        let child_table = row.get::<_, String>(0)?;
        let parent_table = row.get::<_, String>(2)?;
        let count = groups.entry((child_table, parent_table)).or_insert(0_u64);
        *count = count
            .checked_add(1)
            .context("foreign-key violation count overflow")?;
    }
    Ok(groups
        .into_iter()
        .map(
            |((child_table, parent_table), rows)| ForeignKeyViolationSummary {
                child_table,
                parent_table,
                rows,
            },
        )
        .collect())
}

fn install_and_readback<V>(
    database: &Path,
    candidate: &Path,
    recovery_directory: &Path,
    backup_database: &Path,
    snapshot_directory: &Path,
    original_counts: &BTreeMap<&'static str, TableObservation>,
    validate: V,
) -> Result<(Option<String>, InstalledReadback)>
where
    V: FnOnce(&Path, &Path, &BTreeMap<&'static str, TableObservation>) -> Result<InstalledReadback>,
{
    let durability_warning =
        install_candidate(database, candidate, recovery_directory, backup_database)?;
    let readback = match validate(database, recovery_directory, original_counts) {
        Ok(readback) => readback,
        Err(error) => {
            return rollback_failed_readback(
                database,
                backup_database,
                snapshot_directory,
                &format!("installed catalog read-back failed: {error}"),
            );
        }
    };
    if !readback.is_valid() {
        return rollback_failed_readback(
            database,
            backup_database,
            snapshot_directory,
            "installed catalog failed application/read-back validation",
        );
    }
    Ok((durability_warning, readback))
}

// Report installation errors without hiding partial sidecar restoration failures
fn installation_error(
    error: std::io::Error,
    moved: &[(PathBuf, PathBuf)],
    recovery_directory: &Path,
    action: &str,
) -> anyhow::Error {
    let restore_errors = restore_moved_sidecars(moved);
    if restore_errors.is_empty() {
        anyhow::Error::new(error).context(action.to_owned())
    } else {
        anyhow::anyhow!(
            "{action} failed ({error}); sidecar restoration was incomplete: {}; recovery snapshot retained at {}",
            restore_errors.join("; "),
            recovery_directory.display()
        )
    }
}

// Restore every moved sidecar without overwriting a path another writer recreated
fn restore_moved_sidecars(moved: &[(PathBuf, PathBuf)]) -> Vec<String> {
    let mut failures = Vec::new();
    for (live, archived) in moved.iter().rev() {
        match fs::hard_link(archived, live) {
            Ok(()) => {
                if let Err(error) = fs::remove_file(archived) {
                    failures.push(format!("{}: {error}", archived.display()));
                }
            }
            Err(_error) if same_file_identity(archived, live) => {
                if let Err(remove_error) = fs::remove_file(archived) {
                    failures.push(format!("{}: {remove_error}", archived.display()));
                }
            }
            Err(error) => failures.push(format!("{}: {error}", live.display())),
        }
    }
    failures
}

// Restore the original snapshot as a staged multi-file operation without clobbering live paths
fn restore_snapshot(
    database: &Path,
    backup_database: &Path,
    snapshot_directory: &Path,
) -> Result<()> {
    restore_snapshot_with_ops(
        database,
        backup_database,
        snapshot_directory,
        |source, destination| fs::rename(source, destination),
        |source, destination| fs::hard_link(source, destination),
    )
}

fn restore_snapshot_with_ops<R, H>(
    database: &Path,
    backup_database: &Path,
    snapshot_directory: &Path,
    mut rename_path: R,
    mut hard_link: H,
) -> Result<()>
where
    R: FnMut(&Path, &Path) -> std::io::Result<()>,
    H: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    ensure_regular_file(backup_database)?;
    let parent = database
        .parent()
        .context("catalog path has no parent directory")?;
    let restore_directory = create_recovery_directory(snapshot_directory, database)?;
    let staged_database = restore_directory.join("restored.sqlite");
    copy_private_file_new(backup_database, &staged_database)?;

    let mut staged_files = vec![(staged_database.clone(), database.to_path_buf())];
    for suffix in SIDECAR_SUFFIXES {
        let backup_sidecar = append_suffix(backup_database, suffix);
        if !regular_file_exists(&backup_sidecar)? {
            continue;
        }
        let staged_sidecar = append_suffix(&staged_database, suffix);
        copy_private_file_new(&backup_sidecar, &staged_sidecar)?;
        staged_files.push((staged_sidecar, append_suffix(database, suffix)));
    }
    sync_directory(&restore_directory)?;

    let mut current_files = vec![database.to_path_buf()];
    ensure_regular_file(database)?;
    for suffix in SIDECAR_SUFFIXES {
        let live_sidecar = append_suffix(database, suffix);
        if regular_file_exists(&live_sidecar)? {
            current_files.push(live_sidecar);
        }
    }
    let mut quarantined = Vec::new();
    for (index, live) in current_files.iter().enumerate() {
        let quarantine = restore_directory.join(format!("previous-{index}"));
        if let Err(error) = rename_path(live, &quarantine) {
            let restore_errors = restore_quarantined(&quarantined, &mut hard_link);
            if restore_errors.is_empty() {
                let _ = fs::remove_dir_all(&restore_directory);
                return Err(error)
                    .context("moving the installed catalog aside for snapshot restore");
            }
            return Err(anyhow::anyhow!(
                "snapshot restore could not quiesce {} ({error}); previous catalog restoration was incomplete: {}; original backup remains at {} and staging at {}",
                live.display(),
                restore_errors.join("; "),
                backup_database.display(),
                restore_directory.display()
            ));
        }
        quarantined.push((live.clone(), quarantine));
    }

    let mut linked = Vec::new();
    for (staged, live) in &staged_files {
        if let Err(error) = hard_link(staged, live) {
            let mut rollback_errors = remove_restored_links(&linked);
            rollback_errors.extend(restore_quarantined(&quarantined, &mut hard_link));
            if rollback_errors.is_empty() {
                let _ = fs::remove_dir_all(&restore_directory);
                return Err(error).context("linking the original snapshot into the catalog path");
            }
            return Err(anyhow::anyhow!(
                "snapshot restore failed at {} ({error}); rollback was incomplete: {}; original backup remains at {} and staging at {}",
                live.display(),
                rollback_errors.join("; "),
                backup_database.display(),
                restore_directory.display()
            ));
        }
        linked.push((staged.clone(), live.clone()));
    }

    if let Err(error) = sync_directory(parent) {
        return Err(anyhow::anyhow!(
            "original snapshot contents were restored but directory durability is unconfirmed ({error}); backup remains at {} and staging at {}",
            backup_database.display(),
            restore_directory.display()
        ));
    }
    fs::remove_dir_all(&restore_directory).with_context(|| {
        format!(
            "original snapshot restored, but temporary staging cleanup failed; backup remains at {}",
            backup_database.display()
        )
    })?;
    sync_directory(snapshot_directory).context("syncing the retained original catalog snapshot")?;
    sync_directory(parent).context("syncing restored catalog directory cleanup")?;
    Ok(())
}

fn rollback_failed_readback<T>(
    database: &Path,
    backup_database: &Path,
    snapshot_directory: &Path,
    reason: &str,
) -> Result<T> {
    match restore_snapshot(database, backup_database, snapshot_directory) {
        Ok(()) => bail!("{reason}; original snapshot restored"),
        Err(error) => bail!(
            "{reason}; restoring original snapshot failed: {error}; original backup remains at {}",
            backup_database.display()
        ),
    }
}

// Restore every quarantined pre-restore file, attempting all paths even after an error
fn restore_quarantined<H>(quarantined: &[(PathBuf, PathBuf)], hard_link: &mut H) -> Vec<String>
where
    H: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    let mut failures = Vec::new();
    for (live, archived) in quarantined.iter().rev() {
        match hard_link(archived, live) {
            Ok(()) => {
                if let Err(error) = fs::remove_file(archived) {
                    failures.push(format!("{}: {error}", archived.display()));
                }
            }
            Err(_error) if same_file_identity(archived, live) => {
                if let Err(remove_error) = fs::remove_file(archived) {
                    failures.push(format!("{}: {remove_error}", archived.display()));
                }
            }
            Err(error) => failures.push(format!("{}: {error}", live.display())),
        }
    }
    failures
}

// Remove only live links that still reference the staged snapshot files
fn remove_restored_links(linked: &[(PathBuf, PathBuf)]) -> Vec<String> {
    let mut failures = Vec::new();
    for (staged, live) in linked.iter().rev() {
        if !same_file_identity(staged, live) {
            failures.push(format!("{} changed during rollback", live.display()));
            continue;
        }
        if let Err(error) = fs::remove_file(live) {
            failures.push(format!("{}: {error}", live.display()));
        }
    }
    failures
}

// Compare device and inode identity for paths created through hard links
fn same_file_identity(left: &Path, right: &Path) -> bool {
    let (Ok(left), Ok(right)) = (fs::metadata(left), fs::metadata(right)) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len()
    }
}

// Create a private output file without replacing an existing file
fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

// Set owner-only access on a file created by an external SQLite process
fn set_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// Synchronize a completed file before publishing its path
fn sync_file(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

// Synchronize a directory after creating, moving, or publishing entries
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

// Append a SQLite sidecar suffix without changing the catalog basename
fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_brief::Store;
    use rusqlite::Connection;
    use std::{
        io::{Seek, SeekFrom},
        process::Command,
    };
    use tempfile::tempdir;

    #[test]
    fn recovery_table_allowlist_covers_every_embedded_migration_table() {
        for migration in mg_brief::MIGRATIONS {
            for table in migration.tables {
                assert!(
                    CATALOG_TABLES.contains(table),
                    "migration {} introduced uncounted table {table}",
                    migration.name
                );
            }
        }
        assert!(CATALOG_TABLES.contains(&"schema_migrations"));
    }

    #[test]
    fn seed_manifest_requires_unique_canonical_http_sources_and_valid_intervals() {
        let valid = SeedManifest {
            schema: SEED_MANIFEST_SCHEMA.into(),
            source_count: 1,
            sources: vec![HistoricalFeed {
                name: "news".into(),
                url: "https://example.invalid/feed.xml".into(),
                every_seconds: 300,
            }],
        };
        assert!(validate_seed_manifest(&valid).is_ok());

        let mut wrong_count = valid.clone();
        wrong_count.source_count = 2;
        assert!(validate_seed_manifest(&wrong_count).is_err());

        let mut credential_url = valid.clone();
        credential_url.sources[0].url = "https://user:pass@example.invalid/feed.xml".into();
        assert!(validate_seed_manifest(&credential_url).is_err());

        let mut duplicate_name = valid.clone();
        duplicate_name.sources.push(HistoricalFeed {
            name: "news".into(),
            url: "https://example.invalid/other.xml".into(),
            every_seconds: 300,
        });
        duplicate_name.source_count = 2;
        assert!(validate_seed_manifest(&duplicate_name).is_err());

        let mut invalid_interval = valid;
        invalid_interval.sources[0].every_seconds = 1;
        assert!(validate_seed_manifest(&invalid_interval).is_err());
    }

    #[test]
    fn installation_refuses_live_catalog_changes_after_the_private_snapshot() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let snapshot = directory.path().join("snapshot.sqlite");
        let recovery_directory = directory.path().join("recovery");
        create_private_directory(&recovery_directory).unwrap();
        let candidate = recovery_directory.join("candidate.sqlite");
        let initial = Connection::open(&database).unwrap();
        initial
            .execute_batch(
                "CREATE TABLE state (id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO state VALUES (1, 'snapshot');",
            )
            .unwrap();
        drop(initial);
        copy_private_file_new(&database, &snapshot).unwrap();
        let candidate_connection = Connection::open(&candidate).unwrap();
        candidate_connection
            .execute_batch("CREATE TABLE state (id INTEGER PRIMARY KEY, value TEXT NOT NULL);")
            .unwrap();
        drop(candidate_connection);
        let concurrent_write = Connection::open(&database).unwrap();
        concurrent_write
            .execute("UPDATE state SET value = 'newer' WHERE id = 1", [])
            .unwrap();
        drop(concurrent_write);
        let current_bytes = fs::read(&database).unwrap();

        let result = install_candidate(&database, &candidate, &recovery_directory, &snapshot);

        assert!(result.is_err());
        assert!(candidate.is_file());
        assert_eq!(fs::read(&database).unwrap(), current_bytes);
        let readback =
            Connection::open_with_flags(&database, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let value: String = readback
            .query_row("SELECT value FROM state WHERE id = 1", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "newer");
    }

    #[test]
    fn recovery_rejects_a_candidate_that_opens_but_cannot_read_ticker_sources() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let store = Store::open(database.clone(), directory.path().join("artifacts")).unwrap();
        store
            .register("source", "https://example.invalid/feed", None)
            .unwrap();
        drop(store);
        let connection = Connection::open(&database).unwrap();
        connection
            .execute("UPDATE sources SET enabled = 'invalid'", [])
            .unwrap();
        drop(connection);

        let report = recover(&database, false, false, true).unwrap();

        assert!(!report.applied);
        assert!(!report.application_opened_candidate);
        assert_eq!(report.status, "candidate_requires_review");
        let candidate = Store::open(
            report.candidate_database,
            directory.path().join("candidate-artifacts"),
        )
        .unwrap();
        assert!(candidate.list_sources().is_err());
    }

    #[test]
    fn source_rows_are_reseeded_from_the_private_snapshot_with_exact_digest() {
        let directory = tempdir().unwrap();
        let original = directory.path().join("original catalog.sqlite");
        let candidate = directory.path().join("candidate catalog.sqlite");
        for (path, rows) in [
            (
                &original,
                "(1, 'first', 'https://example.invalid/first'), (2, 'second', 'https://example.invalid/second')",
            ),
            (&candidate, "(9, 'stale', 'https://example.invalid/stale')"),
        ] {
            let connection = Connection::open(path).unwrap();
            connection
                .execute_batch(&format!(
                    "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, url TEXT NOT NULL UNIQUE); INSERT INTO sources VALUES {rows};"
                ))
                .unwrap();
        }
        let expected = table_counts(&original)["sources"];

        restore_source_rows_from_snapshot(&original, &candidate, expected).unwrap();

        assert_eq!(table_counts(&candidate)["sources"], expected);
        assert_eq!(table_counts(&original)["sources"], expected);
    }

    #[test]
    fn historical_seed_restore_disambiguates_only_collisions_and_restores_ticker_state() {
        let directory = tempdir().unwrap();
        let original = directory.path().join("original.sqlite");
        let candidate = directory.path().join("candidate.sqlite");
        let schema = "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, user_agent TEXT NOT NULL, enabled INTEGER NOT NULL, created_at TEXT NOT NULL, ticker INTEGER NOT NULL, fetch_interval_seconds INTEGER NOT NULL, last_fetched_at TEXT, etag TEXT, last_modified TEXT);";
        let original_connection = Connection::open(&original).unwrap();
        original_connection.execute_batch(schema).unwrap();
        original_connection
            .execute_batch(
                "INSERT INTO sources VALUES (1, 'news', 'https://example.invalid/first', 'agent', 0, 'created-1', 0, 600, NULL, NULL, NULL), (2, 'news', 'https://example.invalid/other', 'agent', 1, 'created-2', 1, 300, NULL, NULL, NULL);",
            )
            .unwrap();
        drop(original_connection);
        let candidate_connection = Connection::open(&candidate).unwrap();
        candidate_connection.execute_batch(schema).unwrap();
        candidate_connection
            .execute_batch(
                "CREATE UNIQUE INDEX source_name_unique ON sources(name); CREATE UNIQUE INDEX source_url_unique ON sources(url); INSERT INTO sources VALUES (9, 'stale', 'https://example.invalid/stale', 'agent', 1, 'created-9', 0, 300, NULL, NULL, NULL);",
            )
            .unwrap();
        drop(candidate_connection);
        let manifest = SeedManifest {
            schema: SEED_MANIFEST_SCHEMA.into(),
            source_count: 1,
            sources: vec![HistoricalFeed {
                name: "news".into(),
                url: "https://example.invalid/first".into(),
                every_seconds: 900,
            }],
        };
        let expected = table_counts(&original)["sources"];

        let (renamed, normalized, restored_urls, digest) =
            restore_source_rows_from_snapshot_with_manifest(
                &original,
                &candidate,
                expected,
                Some(&manifest),
            )
            .unwrap();

        assert_eq!(renamed, 1);
        assert_eq!(normalized, 0);
        assert_eq!(restored_urls, 0);
        assert_eq!(table_counts(&candidate)["sources"].digest, Some(digest));
        assert!(source_rows_match_manifest_transform(&original, &candidate, &manifest).unwrap());
        let connection = Connection::open(&candidate).unwrap();
        let seed: (String, String, i64, i64, i64) = connection
            .query_row(
                "SELECT name, url, enabled, ticker, fetch_interval_seconds FROM sources WHERE id=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            seed,
            (
                "news".into(),
                "https://example.invalid/first".into(),
                1,
                1,
                900
            )
        );
        let duplicate_name: String = connection
            .query_row("SELECT name FROM sources WHERE id=2", [], |row| row.get(0))
            .unwrap();
        assert_eq!(duplicate_name, "news [source-id:2]");
        let source_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM sources", [], |row| row.get(0))
            .unwrap();
        assert_eq!(source_count, 2);
    }

    #[test]
    fn historical_seed_restores_integer_stored_name_as_text_without_changing_source_identity() {
        let directory = tempdir().unwrap();
        let original = directory.path().join("original.sqlite");
        let candidate = directory.path().join("candidate.sqlite");
        let columns = "id INTEGER PRIMARY KEY, name NOT NULL, url TEXT NOT NULL, user_agent TEXT NOT NULL, enabled INTEGER NOT NULL, created_at TEXT NOT NULL, ticker INTEGER NOT NULL, fetch_interval_seconds INTEGER NOT NULL, last_fetched_at TEXT, etag TEXT, last_modified TEXT";
        let original_connection = Connection::open(&original).unwrap();
        original_connection
            .execute_batch(&format!(
                "CREATE TABLE sources ({columns}); INSERT INTO sources VALUES (1, 123, 'https://example.invalid/seed', 'agent', 0, 'created', 0, 600, NULL, NULL, NULL);"
            ))
            .unwrap();
        drop(original_connection);
        let candidate_connection = Connection::open(&candidate).unwrap();
        candidate_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, user_agent TEXT NOT NULL, enabled INTEGER NOT NULL, created_at TEXT NOT NULL, ticker INTEGER NOT NULL, fetch_interval_seconds INTEGER NOT NULL, last_fetched_at TEXT, etag TEXT, last_modified TEXT); CREATE UNIQUE INDEX source_name_unique ON sources(name); CREATE UNIQUE INDEX source_url_unique ON sources(url); INSERT INTO sources VALUES (9, 'stale', 'https://example.invalid/stale', 'agent', 1, 'created-9', 0, 300, NULL, NULL, NULL);"
            )
            .unwrap();
        drop(candidate_connection);
        let manifest = SeedManifest {
            schema: SEED_MANIFEST_SCHEMA.into(),
            source_count: 1,
            sources: vec![HistoricalFeed {
                name: "historical-name".into(),
                url: "https://example.invalid/seed".into(),
                every_seconds: 300,
            }],
        };
        let expected = table_counts(&original)["sources"];

        let (renamed, normalized, restored_urls, digest) =
            restore_source_rows_from_snapshot_with_manifest(
                &original,
                &candidate,
                expected,
                Some(&manifest),
            )
            .unwrap();

        assert_eq!(renamed, 0);
        assert_eq!(normalized, 1);
        assert_eq!(restored_urls, 0);
        assert_eq!(table_counts(&candidate)["sources"].digest, Some(digest));
        assert!(source_rows_match_manifest_transform(&original, &candidate, &manifest).unwrap());
        let connection = Connection::open(&candidate).unwrap();
        let (name, url, enabled, ticker, interval): (String, String, i64, i64, i64) = connection
            .query_row(
                "SELECT name, url, enabled, ticker, fetch_interval_seconds FROM sources WHERE id=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            (name, url, enabled, ticker, interval),
            (
                "historical-name".into(),
                "https://example.invalid/seed".into(),
                1,
                1,
                300
            )
        );
    }

    #[test]
    fn historical_seed_restores_a_changed_url_only_through_one_provenance_id() {
        let directory = tempdir().unwrap();
        let original = directory.path().join("original.sqlite");
        let candidate = directory.path().join("candidate.sqlite");
        let sources_schema = "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, user_agent TEXT NOT NULL, enabled INTEGER NOT NULL, created_at TEXT NOT NULL, ticker INTEGER NOT NULL, fetch_interval_seconds INTEGER NOT NULL, last_fetched_at TEXT, etag TEXT, last_modified TEXT);";
        let original_connection = Connection::open(&original).unwrap();
        original_connection.execute_batch(sources_schema).unwrap();
        original_connection
            .execute_batch(
                "CREATE TABLE fetch_runs (id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL, http_status INTEGER, final_url TEXT, error TEXT); CREATE TABLE provenance (id INTEGER PRIMARY KEY, fetch_run_id INTEGER NOT NULL, artifact_id INTEGER NOT NULL, item_id INTEGER, source_url TEXT NOT NULL, fetched_at TEXT NOT NULL); INSERT INTO sources VALUES (1, 'news', 'https://example.invalid/changed', 'agent', 1, 'created', 0, 600, NULL, NULL, NULL); INSERT INTO fetch_runs VALUES (1, 1, 'started', 'finished', 'ok', 200, NULL, NULL); INSERT INTO provenance VALUES (1, 1, 1, NULL, 'https://example.invalid/seed', 'fetched');",
            )
            .unwrap();
        drop(original_connection);
        let candidate_connection = Connection::open(&candidate).unwrap();
        candidate_connection.execute_batch(sources_schema).unwrap();
        candidate_connection
            .execute_batch(
                "CREATE UNIQUE INDEX source_name_unique ON sources(name); CREATE UNIQUE INDEX source_url_unique ON sources(url); INSERT INTO sources VALUES (9, 'stale', 'https://example.invalid/stale', 'agent', 1, 'created-9', 0, 300, NULL, NULL, NULL);",
            )
            .unwrap();
        drop(candidate_connection);
        let manifest = SeedManifest {
            schema: SEED_MANIFEST_SCHEMA.into(),
            source_count: 1,
            sources: vec![HistoricalFeed {
                name: "news".into(),
                url: "https://example.invalid/seed".into(),
                every_seconds: 300,
            }],
        };
        let expected = table_counts(&original)["sources"];

        let (renamed, normalized, restored_urls, digest) =
            restore_source_rows_from_snapshot_with_manifest(
                &original,
                &candidate,
                expected,
                Some(&manifest),
            )
            .unwrap();

        assert_eq!(renamed, 0);
        assert_eq!(normalized, 0);
        assert_eq!(restored_urls, 1);
        assert_eq!(table_counts(&candidate)["sources"].digest, Some(digest));
        assert!(source_rows_match_manifest_transform(&original, &candidate, &manifest).unwrap());
        let connection = Connection::open(&candidate).unwrap();
        let restored: (i64, String) = connection
            .query_row("SELECT id, url FROM sources", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(restored, (1, "https://example.invalid/seed".into()));
    }

    #[test]
    fn historical_seed_can_resolve_one_changed_url_by_its_unique_historical_name() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL); INSERT INTO sources VALUES (7, 'news', 'https://example.invalid/changed');",
            )
            .unwrap();
        let manifest = SeedManifest {
            schema: SEED_MANIFEST_SCHEMA.into(),
            source_count: 1,
            sources: vec![HistoricalFeed {
                name: "news".into(),
                url: "https://example.invalid/seed".into(),
                every_seconds: 300,
            }],
        };

        let transform = build_source_transform(&connection, "main", Some(&manifest)).unwrap();

        assert_eq!(transform.restored_urls, 1);
        assert_eq!(
            transform.overrides[&7].url.as_deref(),
            Some("https://example.invalid/seed")
        );
    }

    #[test]
    fn orphan_provenance_pruning_preserves_feed_items_and_valid_provenance() {
        let directory = tempdir().unwrap();
        let candidate = directory.path().join("candidate.sqlite");
        let connection = Connection::open(&candidate).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys=OFF; CREATE TABLE fetch_runs (id INTEGER PRIMARY KEY); CREATE TABLE artifacts (id INTEGER PRIMARY KEY); CREATE TABLE feed_items (id INTEGER PRIMARY KEY); CREATE TABLE provenance (id INTEGER PRIMARY KEY, fetch_run_id INTEGER NOT NULL REFERENCES fetch_runs(id), artifact_id INTEGER NOT NULL REFERENCES artifacts(id), item_id INTEGER REFERENCES feed_items(id)); INSERT INTO fetch_runs VALUES (1); INSERT INTO artifacts VALUES (1); INSERT INTO feed_items VALUES (1); INSERT INTO provenance VALUES (1, 1, 1, 1), (2, 1, 99, 1), (3, 1, 1, 99), (4, 99, 1, NULL);",
            )
            .unwrap();
        drop(connection);

        let pruned = prune_orphan_provenance(&candidate).unwrap();

        assert_eq!(pruned, 3);
        let connection = Connection::open(&candidate).unwrap();
        let item_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM feed_items", [], |row| row.get(0))
            .unwrap();
        let provenance_ids: Vec<i64> = connection
            .prepare("SELECT id FROM provenance ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(item_count, 1);
        assert_eq!(provenance_ids, vec![1]);
        assert!(catalog_foreign_key_violations(&candidate)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn source_reseed_refuses_unreadable_original_without_changing_candidate_rows() {
        let directory = tempdir().unwrap();
        let original = directory.path().join("unreadable.sqlite");
        let candidate = directory.path().join("candidate.sqlite");
        fs::write(&original, b"not a database").unwrap();
        let connection = Connection::open(&candidate).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (7, 'keep');",
            )
            .unwrap();
        drop(connection);
        let before = table_counts(&candidate)["sources"];

        assert!(restore_source_rows_from_snapshot(
            &original,
            &candidate,
            TableObservation {
                rows: RowCount::Unreadable,
                digest: None,
            },
        )
        .is_err());

        assert_eq!(table_counts(&candidate)["sources"], before);
    }

    #[test]
    fn source_reseed_reports_duplicate_unique_keys_without_mutating_candidate() {
        let directory = tempdir().unwrap();
        let original = directory.path().join("original.sqlite");
        let candidate = directory.path().join("candidate.sqlite");
        let original_connection = Connection::open(&original).unwrap();
        original_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL); INSERT INTO sources VALUES (1, 'Feed', 'https://example.invalid/one'), (2, 'feed', 'https://example.invalid/two');",
            )
            .unwrap();
        drop(original_connection);
        let candidate_connection = Connection::open(&candidate).unwrap();
        candidate_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL); CREATE UNIQUE INDEX source_name_nocase ON sources(name COLLATE NOCASE); CREATE UNIQUE INDEX source_url_unique ON sources(url); INSERT INTO sources VALUES (9, 'keep', 'https://example.invalid/keep');",
            )
            .unwrap();
        drop(candidate_connection);
        let expected = table_counts(&original)["sources"];
        let before = table_counts(&candidate)["sources"];

        let error = restore_source_rows_from_snapshot(&original, &candidate, expected)
            .unwrap_err()
            .to_string();

        assert!(error.contains("duplicate_groups=Some(1)"));
        assert!(error.contains("duplicate_groups=Some(0)"));
        assert_eq!(table_counts(&candidate)["sources"], before);
        assert_eq!(table_counts(&original)["sources"], expected);
    }

    #[test]
    fn source_reseed_rejects_schema_mismatch_without_changing_candidate_rows() {
        let directory = tempdir().unwrap();
        let original = directory.path().join("original.sqlite");
        let candidate = directory.path().join("candidate.sqlite");
        let original_connection = Connection::open(&original).unwrap();
        original_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (1, 'original');",
            )
            .unwrap();
        drop(original_connection);
        let candidate_connection = Connection::open(&candidate).unwrap();
        candidate_connection
            .execute_batch(
                "CREATE TABLE sources (name TEXT NOT NULL, id INTEGER PRIMARY KEY); INSERT INTO sources VALUES ('keep', 9);",
            )
            .unwrap();
        drop(candidate_connection);
        let expected = table_counts(&original)["sources"];
        let before = table_counts(&candidate)["sources"];

        assert!(restore_source_rows_from_snapshot(&original, &candidate, expected).is_err());

        assert_eq!(table_counts(&candidate)["sources"], before);
        assert_eq!(table_counts(&original)["sources"], expected);
    }

    #[test]
    fn source_reseed_constraint_failure_rolls_back_candidate_transaction() {
        let directory = tempdir().unwrap();
        let original = directory.path().join("original.sqlite");
        let candidate = directory.path().join("candidate.sqlite");
        let original_connection = Connection::open(&original).unwrap();
        original_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL); INSERT INTO sources VALUES (1, 'accepted', 'https://example.invalid/accepted'), (2, 'reject', 'https://example.invalid/reject');",
            )
            .unwrap();
        drop(original_connection);
        let candidate_connection = Connection::open(&candidate).unwrap();
        candidate_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL CHECK(name <> 'reject'), url TEXT NOT NULL); INSERT INTO sources VALUES (9, 'keep', 'https://example.invalid/keep');",
            )
            .unwrap();
        drop(candidate_connection);
        let expected = table_counts(&original)["sources"];
        let before = table_counts(&candidate)["sources"];

        assert!(restore_source_rows_from_snapshot(&original, &candidate, expected).is_err());

        assert_eq!(table_counts(&candidate)["sources"], before);
        assert_eq!(table_counts(&original)["sources"], expected);
    }

    #[test]
    fn approved_record_loss_accepts_only_strict_subsets_of_allowed_rows() {
        let directory = tempdir().unwrap();
        let original = directory.path().join("original.sqlite");
        let candidate = directory.path().join("candidate.sqlite");
        for (path, source_rows) in [
            (&original, "(1, 'one'), (2, 'two')"),
            (&candidate, "(2, 'two')"),
        ] {
            let connection = Connection::open(path).unwrap();
            connection
                .execute_batch(&format!(
                    "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES {source_rows}; CREATE TABLE feed_items (id INTEGER PRIMARY KEY, title TEXT NOT NULL); INSERT INTO feed_items VALUES (1, 'same');"
                ))
                .unwrap();
        }
        let original_counts = table_counts(&original);
        let candidate_counts = table_counts(&candidate);

        assert!(record_state_matches_policy(
            &original,
            &candidate,
            &original_counts,
            &candidate_counts,
        )
        .unwrap());
    }

    #[test]
    fn policy_validation_preserves_original_wal_bundle_bytes() {
        let directory = tempdir().unwrap();
        let original = directory.path().join("original.sqlite");
        let candidate = directory.path().join("candidate.sqlite");
        let original_connection = Connection::open(&original).unwrap();
        let original_mode: String = original_connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(original_mode, "wal");
        original_connection
            .execute_batch(
                "PRAGMA wal_autocheckpoint=0; CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (1, 'same');",
            )
            .unwrap();
        let candidate_connection = Connection::open(&candidate).unwrap();
        let candidate_mode: String = candidate_connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(candidate_mode, "wal");
        candidate_connection
            .execute_batch(
                "PRAGMA wal_autocheckpoint=0; CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (1, 'same');",
            )
            .unwrap();
        let original_wal = append_suffix(&original, "-wal");
        let original_shm = append_suffix(&original, "-shm");
        let candidate_wal = append_suffix(&candidate, "-wal");
        let candidate_shm = append_suffix(&candidate, "-shm");
        assert!(original_wal.is_file() && original_shm.is_file());
        assert!(candidate_wal.is_file() && candidate_shm.is_file());
        let original_counts = table_counts(&original);
        let candidate_counts = table_counts(&candidate);
        let source_files = [
            &original,
            &original_wal,
            &original_shm,
            &candidate,
            &candidate_wal,
            &candidate_shm,
        ]
        .into_iter()
        .map(|path| (path.to_path_buf(), fs::read(path).unwrap()))
        .collect::<BTreeMap<_, _>>();

        assert!(record_state_matches_policy(
            &original,
            &candidate,
            &original_counts,
            &candidate_counts,
        )
        .unwrap());

        let after_files = source_files
            .keys()
            .map(|path| (path.clone(), fs::read(path).unwrap()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(after_files, source_files);
        drop(original_connection);
        drop(candidate_connection);
    }

    #[test]
    fn record_policy_rejects_schema_only_drift_and_unlisted_table_data_changes() {
        let directory = tempdir().unwrap();
        let original = directory.path().join("original.sqlite");
        let schema_drift = directory.path().join("schema-drift.sqlite");
        let original_connection = Connection::open(&original).unwrap();
        original_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (1, 'same'); CREATE TABLE local_extension (id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO local_extension VALUES (1, 'same');",
            )
            .unwrap();
        drop(original_connection);
        let schema_connection = Connection::open(&schema_drift).unwrap();
        schema_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL CHECK(name <> 'blocked')); INSERT INTO sources VALUES (1, 'same'); CREATE TABLE local_extension (id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO local_extension VALUES (1, 'same');",
            )
            .unwrap();
        drop(schema_connection);
        let original_counts = table_counts(&original);
        let schema_counts = table_counts(&schema_drift);
        assert!(!record_state_matches_policy(
            &original,
            &schema_drift,
            &original_counts,
            &schema_counts,
        )
        .unwrap());

        let changed_unlisted = directory.path().join("changed-unlisted.sqlite");
        let changed_connection = Connection::open(&changed_unlisted).unwrap();
        changed_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (1, 'same'); CREATE TABLE local_extension (id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO local_extension VALUES (1, 'changed');",
            )
            .unwrap();
        drop(changed_connection);
        let changed_counts = table_counts(&changed_unlisted);
        assert!(!record_state_matches_policy(
            &original,
            &changed_unlisted,
            &original_counts,
            &changed_counts,
        )
        .unwrap());

        let added_unlisted = directory.path().join("added-unlisted.sqlite");
        let added_connection = Connection::open(&added_unlisted).unwrap();
        added_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (1, 'same'); CREATE TABLE local_extension (id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO local_extension VALUES (1, 'same'); CREATE TABLE unexpected (id INTEGER PRIMARY KEY);",
            )
            .unwrap();
        drop(added_connection);
        let added_counts = table_counts(&added_unlisted);
        assert!(!record_state_matches_policy(
            &original,
            &added_unlisted,
            &original_counts,
            &added_counts,
        )
        .unwrap());

        let empty_lost_and_found = directory.path().join("empty-lost-and-found.sqlite");
        let lost_and_found_connection = Connection::open(&empty_lost_and_found).unwrap();
        lost_and_found_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (1, 'same'); CREATE TABLE local_extension (id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO local_extension VALUES (1, 'same'); CREATE TABLE lost_and_found (rootpgno INTEGER, pgno INTEGER, nfield INTEGER, id INTEGER, c0); CREATE INDEX lost_and_found_idx ON lost_and_found(rootpgno); CREATE TRIGGER lost_and_found_trigger AFTER INSERT ON lost_and_found BEGIN SELECT 1; END;",
            )
            .unwrap();
        drop(lost_and_found_connection);
        let lost_and_found_counts = table_counts(&empty_lost_and_found);
        assert!(has_no_unmapped_rows(&lost_and_found_counts));
        assert!(!record_state_matches_policy(
            &original,
            &empty_lost_and_found,
            &original_counts,
            &lost_and_found_counts,
        )
        .unwrap());
    }

    #[test]
    fn approved_record_loss_rejects_replacement_addition_unreadable_and_unmapped_rows() {
        let directory = tempdir().unwrap();
        let original = directory.path().join("original.sqlite");
        let candidate = directory.path().join("candidate.sqlite");
        let original_connection = Connection::open(&original).unwrap();
        original_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (1, 'one'), (2, 'two'); CREATE TABLE feed_items (id INTEGER PRIMARY KEY, title TEXT NOT NULL); INSERT INTO feed_items VALUES (1, 'same');",
            )
            .unwrap();
        drop(original_connection);
        let candidate_connection = Connection::open(&candidate).unwrap();
        candidate_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (1, 'replacement'); CREATE TABLE feed_items (id INTEGER PRIMARY KEY, title TEXT NOT NULL); INSERT INTO feed_items VALUES (1, 'same');",
            )
            .unwrap();
        drop(candidate_connection);
        let original_counts = table_counts(&original);
        let mut candidate_counts = table_counts(&candidate);
        assert!(!record_state_matches_policy(
            &original,
            &candidate,
            &original_counts,
            &candidate_counts,
        )
        .unwrap());

        let added = directory.path().join("added.sqlite");
        let added_connection = Connection::open(&added).unwrap();
        added_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (1, 'one'), (2, 'two'), (3, 'added'); CREATE TABLE feed_items (id INTEGER PRIMARY KEY, title TEXT NOT NULL); INSERT INTO feed_items VALUES (1, 'same');",
            )
            .unwrap();
        drop(added_connection);
        let added_counts = table_counts(&added);
        assert!(
            !record_state_matches_policy(&original, &added, &original_counts, &added_counts,)
                .unwrap()
        );

        let changed_other_table = directory.path().join("changed-other-table.sqlite");
        let changed_connection = Connection::open(&changed_other_table).unwrap();
        changed_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (2, 'two'); CREATE TABLE feed_items (id INTEGER PRIMARY KEY, title TEXT NOT NULL); INSERT INTO feed_items VALUES (1, 'changed');",
            )
            .unwrap();
        drop(changed_connection);
        let changed_counts = table_counts(&changed_other_table);
        assert!(!record_state_matches_policy(
            &original,
            &changed_other_table,
            &original_counts,
            &changed_counts,
        )
        .unwrap());

        candidate_counts.insert(
            "schema_migrations",
            TableObservation {
                rows: RowCount::Unreadable,
                digest: None,
            },
        );
        assert!(!record_state_matches_policy(
            &original,
            &candidate,
            &original_counts,
            &candidate_counts,
        )
        .unwrap());

        let unmapped = directory.path().join("unmapped.sqlite");
        let unmapped_connection = Connection::open(&unmapped).unwrap();
        unmapped_connection
            .execute_batch(
                "CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL); INSERT INTO sources VALUES (2, 'two'); CREATE TABLE feed_items (id INTEGER PRIMARY KEY, title TEXT NOT NULL); INSERT INTO feed_items VALUES (1, 'same'); CREATE TABLE lost_and_found (id INTEGER PRIMARY KEY, payload TEXT); INSERT INTO lost_and_found VALUES (1, 'unknown');",
            )
            .unwrap();
        drop(unmapped_connection);
        let unmapped_counts = table_counts(&unmapped);
        assert!(!record_state_matches_policy(
            &original,
            &unmapped,
            &original_counts,
            &unmapped_counts,
        )
        .unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn recovery_cli_timeout_and_nonzero_exit_fail_closed() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let directory = tempdir().unwrap();
        let backup = directory.path().join("backup.sqlite");
        let timed_out_cli = directory.path().join("timed-out-sqlite");
        let failing_cli = directory.path().join("failing-sqlite");
        fs::write(&backup, b"temporary fixture").unwrap();
        fs::write(&timed_out_cli, "#!/bin/sh\nexec /usr/bin/sleep 5\n").unwrap();
        fs::write(&failing_cli, "#!/bin/sh\nexit 23\n").unwrap();
        for cli in [&timed_out_cli, &failing_cli] {
            fs::set_permissions(cli, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let timeout_start = Instant::now();
        assert!(run_recover_with(
            &backup,
            &directory.path().join("timeout.sql"),
            timed_out_cli.to_str().unwrap(),
            "0.05s",
        )
        .is_err());
        assert!(timeout_start.elapsed() < std::time::Duration::from_secs(3));
        assert!(run_recover_with(
            &backup,
            &directory.path().join("failure.sql"),
            failing_cli.to_str().unwrap(),
            "300s",
        )
        .is_err());
    }

    #[test]
    fn recovery_import_enforces_candidate_page_limit_before_growth() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source.sqlite");
        let connection = Connection::open(&source).unwrap();
        connection.execute_batch("PRAGMA page_size=512;").unwrap();
        connection
            .execute_batch("CREATE TABLE rows (id INTEGER PRIMARY KEY, value TEXT);")
            .unwrap();
        for _ in 0..100 {
            connection
                .execute("INSERT INTO rows (value) VALUES (?1)", ["x".repeat(512)])
                .unwrap();
        }
        drop(connection);

        let recovered_sql = directory.path().join("recovered.sql");
        let candidate = directory.path().join("candidate.sqlite");
        run_recover(&source, &recovered_sql).unwrap();
        let page_size = recovered_page_size(&recovered_sql).unwrap();
        let source_bytes = fs::read(&source).unwrap();

        assert!(import_recovered_sql(&recovered_sql, &candidate, u64::from(page_size)).is_err());
        assert!(fs::metadata(&candidate).unwrap().len() <= u64::from(page_size));
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
    }

    #[test]
    fn recovered_sql_cannot_raise_the_hard_candidate_file_limit() {
        let directory = tempdir().unwrap();
        let recovered_sql = directory.path().join("recovered.sql");
        let candidate = directory.path().join("candidate.sqlite");
        fs::write(
            &recovered_sql,
            r#"PRAGMA page_size = '4096';
PRAGMA max_page_count = 100000;
CREATE TABLE payload (value BLOB);
BEGIN;
WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100) INSERT INTO payload SELECT randomblob(3000) FROM n;
COMMIT;
"#,
        )
        .unwrap();

        assert!(import_recovered_sql(&recovered_sql, &candidate, 8192).is_err());
        assert!(fs::metadata(&candidate).unwrap().len() <= 8192);
    }

    #[test]
    fn candidate_bundle_limit_counts_main_database_and_sidecars() {
        let directory = tempdir().unwrap();
        let candidate = directory.path().join("candidate.sqlite");
        fs::write(&candidate, b"database").unwrap();
        fs::write(append_suffix(&candidate, "-wal"), b"sidecar").unwrap();

        assert!(ensure_candidate_bundle_size(&candidate, 12).is_err());
        assert!(ensure_candidate_bundle_size(&candidate, 15).is_ok());
    }

    #[test]
    fn foreign_key_validation_rejects_unmapped_child_rows() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys=OFF; CREATE TABLE parents (id INTEGER PRIMARY KEY); CREATE TABLE children (parent_id INTEGER REFERENCES parents(id)); INSERT INTO children VALUES (7);",
            )
            .unwrap();
        drop(connection);

        let violations = catalog_foreign_key_violations(&database).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].child_table, "children");
        assert_eq!(violations[0].parent_table, "parents");
        assert_eq!(violations[0].rows, 1);
        assert!(!catalog_foreign_keys_valid(&database).unwrap());

        let repair = Connection::open(&database).unwrap();
        repair
            .execute("INSERT INTO parents VALUES (7)", [])
            .unwrap();
        drop(repair);
        assert!(catalog_foreign_keys_valid(&database).unwrap());
    }

    #[test]
    fn safe_import_rejects_shell_commands_from_recovery_sql() {
        let directory = tempdir().unwrap();
        let recovered_sql = directory.path().join("recovered.sql");
        let candidate = directory.path().join("candidate.sqlite");
        let marker = directory.path().join("shell-ran");
        fs::write(
            &recovered_sql,
            format!(
                "PRAGMA page_size = '4096';\n.shell /usr/bin/touch {}\n",
                marker.display()
            ),
        )
        .unwrap();

        assert!(import_recovered_sql(&recovered_sql, &candidate, 4096).is_err());
        assert!(!marker.exists());
    }

    #[test]
    fn safe_import_rejects_attach_side_effects_from_recovery_sql() {
        let directory = tempdir().unwrap();
        let recovered_sql = directory.path().join("recovered.sql");
        let candidate = directory.path().join("candidate.sqlite");
        let attached_database = directory.path().join("attached.sqlite");
        let escaped_path = attached_database.to_string_lossy().replace('\'', "''");
        fs::write(
            &recovered_sql,
            format!(
                "PRAGMA page_size = '4096';\nATTACH DATABASE '{escaped_path}' AS external;\nCREATE TABLE external.marker (id INTEGER);\n"
            ),
        )
        .unwrap();

        assert!(import_recovered_sql(&recovered_sql, &candidate, 8192).is_err());
        assert!(!attached_database.exists());
    }

    #[test]
    fn recovered_page_size_accepts_supported_power_of_two_boundaries() {
        let directory = tempdir().unwrap();
        let sql_path = directory.path().join("header.sql");

        for page_size in [512, 1024, 4096, 65_536] {
            fs::write(&sql_path, format!("PRAGMA page_size = '{page_size}';\n")).unwrap();
            assert_eq!(recovered_page_size(&sql_path).unwrap(), page_size);
        }
    }

    #[test]
    fn recovered_page_size_rejects_missing_malformed_and_unsupported_headers() {
        let directory = tempdir().unwrap();
        let sql_path = directory.path().join("header.sql");
        let mut invalid_headers = vec![
            String::new(),
            "PRAGMA page_size = 'abc';\n".to_owned(),
            "PRAGMA page_size = '1000';\n".to_owned(),
            "PRAGMA page_size = '131072';\n".to_owned(),
            "PRAGMA page_size = '256';\n".to_owned(),
            "PRAGMA page_size='4096';\n".to_owned(),
        ];
        invalid_headers.push(format!(
            "{}PRAGMA page_size = '4096';\n",
            "-- ignored\n".repeat(32)
        ));

        for header in invalid_headers {
            fs::write(&sql_path, header).unwrap();
            assert!(recovered_page_size(&sql_path).is_err());
        }
    }

    #[test]
    fn recovery_refuses_a_nonempty_lost_and_found_table_end_to_end() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let store = Store::open(database.clone(), directory.path().join("artifacts")).unwrap();
        drop(store);
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE lost_and_found (id INTEGER PRIMARY KEY, payload TEXT); INSERT INTO lost_and_found (payload) VALUES ('unmapped row');",
            )
            .unwrap();
        drop(connection);
        let original_bytes = fs::read(&database).unwrap();

        let report = recover(&database, true, false, true).unwrap();

        assert!(!report.applied);
        assert_eq!(report.status, "candidate_requires_review");
        assert!(!has_no_unmapped_rows(&table_counts(
            &report.candidate_database
        )));
        assert_eq!(fs::read(&database).unwrap(), original_bytes);
        assert!(report.candidate_database.is_file());
    }

    #[test]
    fn same_row_count_with_different_record_content_is_rejected() {
        let absent = TableObservation {
            rows: RowCount::Absent,
            digest: None,
        };
        let mut original = CATALOG_TABLES
            .iter()
            .map(|table| (*table, absent))
            .collect::<BTreeMap<_, _>>();
        let mut recovered = original.clone();
        original.insert(
            "sources",
            TableObservation {
                rows: RowCount::Rows(1),
                digest: Some([1; 32]),
            },
        );
        recovered.insert(
            "sources",
            TableObservation {
                rows: RowCount::Rows(1),
                digest: Some([2; 32]),
            },
        );

        let (comparisons, preserved) = compare_counts(&original, &recovered);

        assert!(!preserved);
        assert!(
            !comparisons
                .iter()
                .find(|comparison| comparison.table == "sources")
                .unwrap()
                .exact_records_match
        );
    }

    #[test]
    fn nonempty_lost_and_found_prevents_installation() {
        let mut observations = CATALOG_TABLES
            .iter()
            .map(|table| {
                (
                    *table,
                    TableObservation {
                        rows: RowCount::Absent,
                        digest: None,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        observations.insert(
            "lost_and_found",
            TableObservation {
                rows: RowCount::Rows(1),
                digest: Some([7; 32]),
            },
        );

        assert!(!has_no_unmapped_rows(&observations));
    }

    #[test]
    fn bounded_snapshot_copy_rejects_oversized_source_without_leaving_partial_file() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source.sqlite");
        let destination = directory.path().join("snapshot.sqlite");
        fs::write(&source, [0x5a; 2048]).unwrap();

        assert!(copy_private_file_bounded(&source, &destination, 1024).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn snapshot_combined_byte_limit_covers_database_and_sidecars() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let snapshot_directory = directory.path().join("snapshot");
        create_private_directory(&snapshot_directory).unwrap();
        let backup_database = snapshot_directory.join("catalog.sqlite");
        fs::write(&database, b"database").unwrap();
        fs::write(append_suffix(&database, "-wal"), b"sidecar").unwrap();

        assert!(snapshot_catalog_with_hook(&database, &backup_database, 12, |_| {}).is_err());
        assert_eq!(fs::read(&backup_database).unwrap(), b"database");
        assert!(!append_suffix(&backup_database, "-wal").exists());
    }

    #[test]
    fn snapshot_rechecks_earlier_files_after_copying_sidecars() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let snapshot_directory = directory.path().join("snapshot");
        create_private_directory(&snapshot_directory).unwrap();
        let backup_database = snapshot_directory.join("catalog.sqlite");
        fs::write(&database, b"original-db").unwrap();
        fs::write(append_suffix(&database, "-wal"), b"wal-state").unwrap();
        let changed_database = database.clone();

        let result =
            snapshot_catalog_with_hook(&database, &backup_database, 1024, move |completed_files| {
                if completed_files == 0 {
                    fs::write(&changed_database, b"revised--db").unwrap();
                }
            });

        assert!(result.is_err());
    }

    #[test]
    fn bounded_snapshot_copy_does_not_remove_a_preexisting_destination() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source.sqlite");
        let destination = directory.path().join("snapshot.sqlite");
        fs::write(&source, b"source").unwrap();
        fs::write(&destination, b"keep existing").unwrap();

        assert!(copy_private_file_bounded(&source, &destination, 1024).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"keep existing");
    }

    #[test]
    fn snapshot_copies_database_and_sidecars_to_owner_only_files() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        fs::write(&database, b"database snapshot").unwrap();
        for suffix in SIDECAR_SUFFIXES {
            fs::write(append_suffix(&database, suffix), suffix.as_bytes()).unwrap();
        }
        let recovery_directory = directory.path().join("recovery");
        create_private_directory(&recovery_directory).unwrap();
        let snapshot_directory = recovery_directory.join("snapshot");
        create_private_directory(&snapshot_directory).unwrap();
        let backup_database = snapshot_directory.join("catalog.sqlite");

        snapshot_catalog(&database, &backup_database).unwrap();

        assert_eq!(fs::read(&backup_database).unwrap(), b"database snapshot");
        for suffix in SIDECAR_SUFFIXES {
            assert_eq!(
                fs::read(append_suffix(&backup_database, suffix)).unwrap(),
                suffix.as_bytes()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&recovery_directory)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&backup_database).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn index_corruption_is_recovered_from_a_private_backup_and_applied() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let artifact_root = directory.path().join("initial-artifacts");
        let store = Store::open(database.clone(), artifact_root).unwrap();
        for index in 0..300 {
            store
                .register(
                    &format!("source-{index}"),
                    &format!("https://example.invalid/{index}"),
                    None,
                )
                .unwrap();
        }
        drop(store);
        checkpoint_candidate(&database).unwrap();
        corrupt_source_index_leaf(&database);
        assert_eq!(
            super::super::integrity::inspect(&database).status_name(),
            "corrupt"
        );
        let before_sources = table_counts(&database).get("sources").copied();
        let original_bytes = fs::read(&database).unwrap();

        let report = recover(&database, true, false, true).unwrap();

        assert!(report.applied);
        assert_eq!(report.status, "installed");
        assert!(report.candidate_integrity.is_healthy());
        assert!(report.application_opened_candidate);
        assert!(report.application_opened_installed);
        assert_eq!(report.original_integrity, "corrupt");
        assert!(report.exact_records_preserved);
        assert!(report.backup_database.is_file());
        assert_eq!(fs::read(&report.backup_database).unwrap(), original_bytes);
        assert!(report.recovery_directory.join("recovered.sql").is_file());
        assert_eq!(
            table_counts(&database).get("sources").copied(),
            before_sources
        );
        assert!(super::super::integrity::inspect(&database).is_healthy());
    }

    #[test]
    fn row_loss_keeps_the_live_catalog_unchanged_and_retains_candidate() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let store = Store::open(database.clone(), directory.path().join("artifacts")).unwrap();
        for index in 0..80 {
            store
                .register(
                    &format!("source-{index}"),
                    &format!("https://example.invalid/{index}"),
                    None,
                )
                .unwrap();
        }
        drop(store);
        checkpoint_candidate(&database).unwrap();
        corrupt_source_table_leaf(&database);
        let original_bytes = fs::read(&database).unwrap();

        let report = recover(&database, true, false, true).unwrap();

        assert!(!report.applied);
        assert_eq!(report.status, "candidate_requires_review");
        assert!(!report.exact_records_preserved);
        assert_eq!(fs::read(&database).unwrap(), original_bytes);
        assert!(report.backup_database.is_file());
        assert_eq!(fs::read(&report.backup_database).unwrap(), original_bytes);
        assert!(report.candidate_database.is_file());
    }

    #[test]
    fn approved_loss_install_revalidates_subset_and_source_rows_after_app_open() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let recovery_directory = directory.path().join("recovery");
        let snapshot_directory = recovery_directory.join("snapshot");
        create_private_directory(&recovery_directory).unwrap();
        create_private_directory(&snapshot_directory).unwrap();
        let backup_database = snapshot_directory.join("catalog.sqlite");
        let candidate = recovery_directory.join("candidate.sqlite");
        let store = Store::open(database.clone(), directory.path().join("artifacts")).unwrap();
        let source = store
            .register("source", "https://example.invalid/feed", None)
            .unwrap();
        let second_source = store
            .register("second", "https://example.invalid/second", None)
            .unwrap();
        drop(store);
        let timestamp = chrono::Utc::now().to_rfc3339();
        let original_connection = Connection::open(&database).unwrap();
        for _ in 0..2 {
            original_connection
                .execute(
                    "INSERT INTO fetch_runs (source_id, started_at, finished_at, status) VALUES (?1, ?2, ?2, 'success')",
                    rusqlite::params![source.id, timestamp],
                )
                .unwrap();
        }
        drop(original_connection);
        checkpoint_candidate(&database).unwrap();
        copy_private_file_new(&database, &backup_database).unwrap();
        copy_private_file_new(&backup_database, &candidate).unwrap();
        let candidate_connection = Connection::open(&candidate).unwrap();
        candidate_connection
            .execute(
                "DELETE FROM fetch_runs WHERE id = (SELECT MAX(id) FROM fetch_runs)",
                [],
            )
            .unwrap();
        candidate_connection
            .execute("DELETE FROM sources WHERE id = ?1", [second_source.id])
            .unwrap();
        drop(candidate_connection);
        checkpoint_candidate(&candidate).unwrap();
        let original_counts = table_counts(&backup_database);

        let (durability_warning, readback) = install_and_readback(
            &database,
            &candidate,
            &recovery_directory,
            &backup_database,
            &snapshot_directory,
            &original_counts,
            |installed_database, recovery, original| {
                read_installed_candidate(
                    installed_database,
                    recovery,
                    original,
                    &backup_database,
                    true,
                )
            },
        )
        .unwrap();

        assert!(durability_warning.is_none());
        assert!(readback.is_valid());
        assert!(readback.record_state_valid);
        assert!(readback.approved_record_loss);
        assert!(!readback.exact_records_preserved);
        assert!(readback.source_rows_accepted);
        assert!(readback.foreign_keys_valid);
        assert!(readback
            .comparisons
            .iter()
            .any(|comparison| comparison.table == "sources"
                && comparison.original == RowCount::Rows(2)
                && comparison.recovered == RowCount::Rows(1)));
        assert!(readback
            .comparisons
            .iter()
            .any(|comparison| comparison.table == "fetch_runs"
                && comparison.original == RowCount::Rows(2)
                && comparison.recovered == RowCount::Rows(1)));
        assert!(backup_database.is_file());
        assert!(super::super::integrity::inspect(&database).is_healthy());
    }

    #[test]
    fn readback_rejects_allowed_source_loss_that_breaks_foreign_keys() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let recovery_directory = directory.path().join("recovery");
        let snapshot_directory = recovery_directory.join("snapshot");
        create_private_directory(&recovery_directory).unwrap();
        create_private_directory(&snapshot_directory).unwrap();
        let backup_database = snapshot_directory.join("catalog.sqlite");
        let candidate = recovery_directory.join("candidate.sqlite");
        let store = Store::open(database.clone(), directory.path().join("artifacts")).unwrap();
        let source = store
            .register("source", "https://example.invalid/feed", None)
            .unwrap();
        drop(store);
        let connection = Connection::open(&database).unwrap();
        connection
            .execute(
                "INSERT INTO feed_items (source_id, identity_key, title, first_seen_at) VALUES (?1, 'fixture-item', 'fixture', ?2)",
                rusqlite::params![source.id, chrono::Utc::now().to_rfc3339()],
            )
            .unwrap();
        drop(connection);
        checkpoint_candidate(&database).unwrap();
        copy_private_file_new(&database, &backup_database).unwrap();
        copy_private_file_new(&backup_database, &candidate).unwrap();
        let candidate_connection = Connection::open(&candidate).unwrap();
        candidate_connection
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .unwrap();
        candidate_connection
            .execute("DELETE FROM sources WHERE id = ?1", [source.id])
            .unwrap();
        drop(candidate_connection);
        checkpoint_candidate(&candidate).unwrap();
        let original_counts = table_counts(&backup_database);

        let readback = read_installed_candidate(
            &candidate,
            &recovery_directory,
            &original_counts,
            &backup_database,
            true,
        )
        .unwrap();

        assert!(readback.application_opened);
        assert!(readback.record_state_valid);
        assert!(readback.approved_record_loss);
        assert!(readback.source_rows_accepted);
        assert!(!readback.foreign_keys_valid);
        assert_eq!(readback.foreign_key_violations.len(), 1);
        assert_eq!(readback.foreign_key_violations[0].child_table, "feed_items");
        assert_eq!(readback.foreign_key_violations[0].parent_table, "sources");
        assert!(!readback.is_valid());
    }

    #[test]
    fn failed_installed_readback_restores_original_snapshot_and_reports_it() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let recovery_directory = directory.path().join("recovery");
        let snapshot_directory = recovery_directory.join("snapshot");
        create_private_directory(&recovery_directory).unwrap();
        create_private_directory(&snapshot_directory).unwrap();
        let backup_database = snapshot_directory.join("catalog.sqlite");
        let candidate = recovery_directory.join("candidate.sqlite");
        let store = Store::open(database.clone(), directory.path().join("artifacts")).unwrap();
        store
            .register("original", "https://example.invalid/feed", None)
            .unwrap();
        drop(store);
        checkpoint_candidate(&database).unwrap();
        copy_private_file_new(&database, &backup_database).unwrap();
        copy_private_file_new(&backup_database, &candidate).unwrap();
        let original_bytes = fs::read(&database).unwrap();
        let original_counts = table_counts(&backup_database);

        let result = install_and_readback(
            &database,
            &candidate,
            &recovery_directory,
            &backup_database,
            &snapshot_directory,
            &original_counts,
            |installed_database, recovery, original| {
                let mut readback = read_installed_candidate(
                    installed_database,
                    recovery,
                    original,
                    &backup_database,
                    false,
                )?;
                assert!(readback.is_valid());
                readback.exact_records_preserved = false;
                Ok(readback)
            },
        );
        let error = result.unwrap_err().to_string();

        assert!(error.contains("original snapshot restored"));
        assert_eq!(fs::read(&database).unwrap(), original_bytes);
        assert_eq!(table_counts(&database), original_counts);
    }

    #[test]
    fn snapshot_restore_failure_reinstates_the_pre_restore_database_and_sidecars() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let snapshot_directory = directory.path().join("snapshot");
        create_private_directory(&snapshot_directory).unwrap();
        let backup_database = snapshot_directory.join("catalog.sqlite");
        fs::write(&backup_database, b"original catalog").unwrap();
        fs::write(&database, b"installed candidate").unwrap();
        for suffix in SIDECAR_SUFFIXES {
            fs::write(
                append_suffix(&backup_database, suffix),
                format!("backup{suffix}"),
            )
            .unwrap();
            fs::write(
                append_suffix(&database, suffix),
                format!("candidate{suffix}"),
            )
            .unwrap();
        }
        let mut hard_link_calls = 0;

        let result = restore_snapshot_with_ops(
            &database,
            &backup_database,
            &snapshot_directory,
            |source, destination| fs::rename(source, destination),
            |source, destination| {
                hard_link_calls += 1;
                if hard_link_calls == 2 {
                    return Err(std::io::Error::other("injected staged-link failure"));
                }
                fs::hard_link(source, destination)
            },
        );

        assert!(result.is_err());
        assert_eq!(fs::read(&database).unwrap(), b"installed candidate");
        for suffix in SIDECAR_SUFFIXES {
            assert_eq!(
                fs::read(append_suffix(&database, suffix)).unwrap(),
                format!("candidate{suffix}").as_bytes()
            );
            assert_eq!(
                fs::read(append_suffix(&backup_database, suffix)).unwrap(),
                format!("backup{suffix}").as_bytes()
            );
        }
        assert_eq!(fs::read(&backup_database).unwrap(), b"original catalog");
    }

    #[test]
    fn snapshot_restore_reports_incomplete_rollback_and_retains_backup() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let snapshot_directory = directory.path().join("snapshot");
        create_private_directory(&snapshot_directory).unwrap();
        let backup_database = snapshot_directory.join("catalog.sqlite");
        fs::write(&backup_database, b"original catalog").unwrap();
        fs::write(&database, b"installed candidate").unwrap();
        for suffix in SIDECAR_SUFFIXES {
            fs::write(
                append_suffix(&backup_database, suffix),
                format!("backup{suffix}"),
            )
            .unwrap();
            fs::write(
                append_suffix(&database, suffix),
                format!("candidate{suffix}"),
            )
            .unwrap();
        }
        let mut hard_link_calls = 0;

        let result = restore_snapshot_with_ops(
            &database,
            &backup_database,
            &snapshot_directory,
            |source, destination| fs::rename(source, destination),
            |source, destination| {
                hard_link_calls += 1;
                if hard_link_calls >= 2 {
                    return Err(std::io::Error::other("persistent injected link failure"));
                }
                fs::hard_link(source, destination)
            },
        );
        let error = result.unwrap_err().to_string();

        assert!(error.contains("rollback was incomplete"));
        assert!(error.contains(&backup_database.display().to_string()));
        assert!(error.contains("staging at"));
        assert_eq!(fs::read(&backup_database).unwrap(), b"original catalog");
        assert!(fs::read_dir(&snapshot_directory).unwrap().count() > 1);
    }

    #[test]
    fn rollback_restores_database_and_sqlite_sidecars_from_snapshot() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let snapshot_directory = directory.path().join("snapshot");
        create_private_directory(&snapshot_directory).unwrap();
        let backup_database = snapshot_directory.join("catalog.sqlite");
        fs::write(&backup_database, b"original catalog").unwrap();
        fs::write(&database, b"recovered candidate").unwrap();
        for suffix in SIDECAR_SUFFIXES {
            fs::write(
                append_suffix(&backup_database, suffix),
                format!("backup{suffix}"),
            )
            .unwrap();
            fs::write(
                append_suffix(&database, suffix),
                format!("candidate{suffix}"),
            )
            .unwrap();
        }

        restore_snapshot(&database, &backup_database, &snapshot_directory).unwrap();

        assert_eq!(fs::read(&database).unwrap(), b"original catalog");
        for suffix in SIDECAR_SUFFIXES {
            assert_eq!(
                fs::read(append_suffix(&database, suffix)).unwrap(),
                format!("backup{suffix}").as_bytes()
            );
        }
    }

    #[test]
    fn restored_wal_and_shm_snapshot_reopens_with_committed_data() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("catalog.sqlite");
        let snapshot_directory = directory.path().join("snapshot");
        create_private_directory(&snapshot_directory).unwrap();
        let backup_database = snapshot_directory.join("catalog.sqlite");
        let connection = Connection::open(&database).unwrap();
        let mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        connection
            .execute_batch(
                "PRAGMA wal_autocheckpoint=0; CREATE TABLE payload (value TEXT); INSERT INTO payload VALUES ('committed in WAL');",
            )
            .unwrap();
        assert!(append_suffix(&database, "-wal").is_file());
        assert!(append_suffix(&database, "-shm").is_file());

        snapshot_catalog(&database, &backup_database).unwrap();
        drop(connection);
        assert!(append_suffix(&backup_database, "-wal").is_file());
        assert!(append_suffix(&backup_database, "-shm").is_file());
        fs::write(&database, b"candidate catalog").unwrap();
        for suffix in SIDECAR_SUFFIXES {
            let live_sidecar = append_suffix(&database, suffix);
            if regular_file_exists(&live_sidecar).unwrap() {
                fs::remove_file(live_sidecar).unwrap();
            }
        }

        restore_snapshot(&database, &backup_database, &snapshot_directory).unwrap();
        let restored =
            Connection::open_with_flags(&database, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let value: String = restored
            .query_row("SELECT value FROM payload", [], |row| row.get(0))
            .unwrap();

        assert_eq!(value, "committed in WAL");
    }

    #[test]
    fn rollback_copy_never_clobbers_an_existing_restore_path() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("backup.sqlite");
        let destination = directory.path().join("restore.sqlite");
        fs::write(&source, b"backup").unwrap();
        fs::write(&destination, b"keep-existing").unwrap();

        let result = copy_private_file_new(&source, &destination);

        assert!(result.is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"keep-existing");
    }

    #[test]
    fn recovery_requires_an_explicit_offline_acknowledgement() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("missing.sqlite");

        let result = recover(&database, false, false, false);

        assert!(result.is_err());
        assert!(!database.exists());
    }

    // Damage a temporary index leaf while preserving its table rows
    fn corrupt_source_index_leaf(database: &Path) {
        corrupt_database_page(database, "sqlite_autoindex_sources_1");
    }

    // Damage a temporary source-table leaf to exercise the row-loss gate
    fn corrupt_source_table_leaf(database: &Path) {
        corrupt_database_page(database, "sources");
    }

    // Corrupt a dbstat-reported page in a test-only catalog
    fn corrupt_database_page(database: &Path, object: &str) {
        let page = Command::new(SQLITE3_PATH)
            .arg(database)
            .arg(format!(
                "SELECT pageno FROM dbstat WHERE name='{}' AND pagetype='leaf' ORDER BY pageno DESC LIMIT 1;",
                object
            ))
            .output()
            .expect("sqlite3 CLI required for recovery tests");
        assert!(page.status.success());
        let page_number: u64 = String::from_utf8(page.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let connection = Connection::open(database).unwrap();
        let page_size: u64 = connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .unwrap();
        drop(connection);
        let offset = (page_number - 1) * page_size;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(database)
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[0]).unwrap();
        file.sync_all().unwrap();
    }
}
