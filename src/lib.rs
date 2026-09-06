pub mod asset;
pub mod cve;

use anyhow::{bail, Context, Result};
use chrono::{Duration as ChronoDuration, Utc};
use cve::{CveRecord, CveVersion, SourceReference, StableId, StorageLocator};
use feed_rs::parser;
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use postgres::{Client as PgClient, NoTls};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    net::{IpAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;

pub const JSON_VERSION: &str = "mg-brief/v1";
pub const INTEROP_SCHEMA: &str = "mg.interop/1";
const MAX_REDIRECTS: usize = 5;
const DEFAULT_USER_AGENT: &str = "mg-brief/0.1 (+local research client)";
// A recently-started run may belong to another active process. Only runs
// older than this are considered abandoned during startup recovery.
const STALE_RUN_AGE: ChronoDuration = ChronoDuration::hours(1);

#[derive(Debug, Clone)]
pub struct Store {
    pub database_url: String,
    pub artifact_root: PathBuf,
    trusted_file_root: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Source {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub user_agent: String,
    pub enabled: bool,
}

impl Serialize for Source {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("Source", 5)?;
        out.serialize_field("id", &self.id)?;
        out.serialize_field("name", &self.name)?;
        out.serialize_field("url", &redact_url(&self.url))?;
        out.serialize_field("user_agent", &"<redacted>")?;
        out.serialize_field("enabled", &self.enabled)?;
        out.end()
    }
}

#[derive(Debug, Serialize)]
pub struct FetchResult {
    pub schema: &'static str,
    pub source: Source,
    pub fetch_run_id: i64,
    pub status: String,
    pub artifact: Option<Artifact>,
    pub items: usize,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Artifact {
    pub id: i64,
    pub sha256: String,
    pub bytes: u64,
    pub path: String,
    pub media_type: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CveArtifactInput {
    pub source_id: StableId,
    pub locator: String,
    pub path: PathBuf,
    pub media_type: String,
}

#[derive(Debug, Serialize)]
pub struct CveIngestResult {
    pub schema: &'static str,
    pub cve_id: String,
    pub version_id: String,
    pub revision: String,
    pub inserted: bool,
    pub current: bool,
}

#[derive(Debug, Serialize)]
pub struct CveCurrent {
    pub schema: &'static str,
    pub record: CveRecord,
    pub version: CveVersion,
}

#[derive(Debug, Serialize)]
pub struct CveHistoryPage {
    pub schema: &'static str,
    pub cve_id: String,
    pub items: Vec<CveHistoryItem>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CveHistoryItem {
    pub record: CveRecord,
    pub version: CveVersion,
}

#[derive(Debug, Serialize, Clone)]
pub struct InteropSnapshot {
    pub interop_schema: &'static str,
    pub kind: &'static str,
    pub producer: InteropProducer,
    pub export_id: String,
    pub created_at: String,
    pub source_revision: String,
    pub records: Vec<InteropRecord>,
    pub links: Vec<serde_json::Value>,
    pub provenance: Vec<InteropRecord>,
    pub diagnostics: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, Clone)]
pub struct InteropProducer {
    pub app: &'static str,
    pub app_version: &'static str,
}

#[derive(Debug, Serialize, Clone)]
pub struct InteropOrigin {
    pub app: &'static str,
    pub kind: String,
    pub local_id: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct InteropRecord {
    pub global_id: String,
    pub origin: InteropOrigin,
    pub revision: i64,
    pub observed_at: String,
    pub payload: serde_json::Value,
}

impl Store {
    pub fn open(db_path: impl Into<PathBuf>, artifact_root: impl Into<PathBuf>) -> Result<Self> {
        Self::open_inner(db_path.into(), artifact_root.into(), None)
    }

    /// Open a store with an explicit, trusted fixture directory for file:// sources
    pub fn open_with_trusted_file_root(
        db_path: impl Into<PathBuf>,
        artifact_root: impl Into<PathBuf>,
        trusted_file_root: impl Into<PathBuf>,
    ) -> Result<Self> {
        Self::open_inner(
            db_path.into(),
            artifact_root.into(),
            Some(trusted_file_root.into()),
        )
    }

    fn open_inner(
        db_path: PathBuf,
        artifact_root: PathBuf,
        trusted_file_root: Option<PathBuf>,
    ) -> Result<Self> {
        if artifact_root.exists()
            && fs::symlink_metadata(&artifact_root)?
                .file_type()
                .is_symlink()
        {
            bail!("artifact root must not be a symlink")
        }
        fs::create_dir_all(&artifact_root)?;
        let root = fs::canonicalize(&artifact_root)?;
        let file_root = trusted_file_root.map(fs::canonicalize).transpose()?;
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let store = Self {
            db_path,
            artifact_root: root,
            trusted_file_root: file_root,
        };
        let mut c = store.conn()?;
        migrate(&mut c)?;
        recover_stale_runs(&c)?;
        Ok(store)
    }

    // A fresh connection per call, deliberately. The CVE commit reconciliation
    // has to open a second, independent connection while a transaction is still
    // outstanding, which one shared client cannot do. PostgreSQL enforces foreign
    // keys always, so there is no equivalent of the PRAGMA this used to set.
    fn conn(&self) -> Result<PgClient> {
        PgClient::connect(&self.database_url, NoTls).context("open catalog")
    }

    pub fn register(
        &self,
        name: &str,
        source_url: &str,
        user_agent: Option<&str>,
    ) -> Result<Source> {
        let parsed = validate_url(source_url)?;
        if parsed.scheme() == "file" && self.trusted_file_root.is_none() {
            bail!("file sources require trusted fixture mode")
        }
        let ua = user_agent.unwrap_or(DEFAULT_USER_AGENT);
        if ua.contains('\r') || ua.contains('\n') || ua.len() > 512 {
            bail!("user-agent is invalid")
        }
        let c = self.conn()?;
        c.execute("INSERT INTO sources(name,url,user_agent,created_at) VALUES ($1,$2,$3,$4) ON CONFLICT(name) DO UPDATE SET url=excluded.url,user_agent=excluded.user_agent,enabled=1", &[&name, &parsed.as_str(), &ua, &Utc::now().to_rfc3339()])?;
        self.source_by_name(name)
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        let c = self.conn()?;
        if c.execute(
            "UPDATE sources SET enabled=$1 WHERE name=$2",
            &[&enabled as i64, &name],
        )? != 1
        {
            bail!("source not found")
        }
        Ok(())
    }

    pub fn source_by_name(&self, name: &str) -> Result<Source> {
        let c = self.conn()?;
        c.query_one("SELECT id,name,url,user_agent,enabled FROM sources WHERE name=$1",
            &[&name],
            source_from_row,
        )
        .optional()?
        .context("source not found")
    }

    pub fn list_sources(&self) -> Result<Vec<Source>> {
        let c = self.conn()?;
        let mut st =
            c.prepare("SELECT id,name,url,user_agent,enabled FROM sources ORDER BY name")?;
        let rows = st
            .query_map([], source_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Transactionally ingest one immutable CVE revision and its authoritative artifacts.
    ///
    /// Current-state ordering is the lexicographic tuple `(modified_at, revision, version_id)`.
    /// Older revisions remain in history but never replace a newer current revision. Reusing a
    /// version ID or `(CVE, revision)` for different content is a hard conflict.
    pub fn ingest_cve(
        &self,
        record: &CveRecord,
        version: &CveVersion,
        artifacts: &[CveArtifactInput],
    ) -> Result<CveIngestResult> {
        self.ingest_cve_with_before_commit(record, version, artifacts, |_| Ok(()))
    }

    fn ingest_cve_with_before_commit<F>(
        &self,
        record: &CveRecord,
        version: &CveVersion,
        artifacts: &[CveArtifactInput],
        before_commit: F,
    ) -> Result<CveIngestResult>
    where
        F: FnOnce(&rusqlite::Transaction<'_>) -> Result<()>,
    {
        record.validate().context("invalid CVE record")?;
        version.validate().context("invalid CVE version")?;
        if record.id != version.cve_id {
            bail!("CVE record and version identity differ")
        }
        if record.modified_at != version.modified_at {
            bail!("CVE record and version modification times differ")
        }
        let record_json = cve::cve_record_storage_json(record)?;
        let version_json = cve::cve_version_storage_json(version)?;
        let references = cve_references(record, version)?;
        let prepared = artifacts
            .iter()
            .map(prepare_cve_artifact)
            .collect::<Result<Vec<_>>>()?;
        for artifact in &prepared {
            if !references.iter().any(|reference| {
                reference.source_id.as_str() == artifact.source_id
                    && reference.locator == artifact.locator
                    && reference.content_sha256.as_deref() == Some(artifact.sha256.as_str())
            }) {
                bail!("CVE artifact is not claimed by provenance")
            }
        }

        let mut c = self.conn()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut installed_paths = Vec::new();
        let outcome = (|| -> Result<CveIngestResult> {
            for artifact in &prepared {
                let relative_path = format!("sha256/{}/{}", &artifact.sha256[..2], artifact.sha256);
                let path = self.artifact_root.join(&relative_path);
                if atomic_write_verified(&path, &artifact.bytes, &artifact.sha256)? {
                    installed_paths.push(path);
                }
                tx.execute(
                    "INSERT INTO artifacts(sha256,byte_len,relative_path,media_type,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(sha256) DO NOTHING",
                    &[&artifact.sha256, &artifact.bytes.len() as i64, &relative_path, &artifact.media_type, &record.provenance.observed_at.to_rfc3339()],
                )?;
                let artifact_id: i64 = tx
                    .query_one("SELECT id FROM artifacts WHERE sha256=$1 AND byte_len=$2 AND relative_path=$3", &[&artifact.sha256, &artifact.bytes.len() as i64, &relative_path]).map(|row| row.get(0))
                    .context("artifact catalog conflict")?;
                tx.execute(
                    "INSERT INTO artifact_owners(source_id,artifact_id,locator) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                    &[&artifact.source_id, &artifact_id, &artifact.locator],
                )?;
            }
            for reference in &references {
                verify_cve_artifact(&tx, &self.artifact_root, reference)?;
            }

            let existing = tx
                .query_one("SELECT record_json,version_json FROM cve_versions WHERE id=$1",
                    &[&version.id.as_str()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            if let Some((existing_record, existing_version)) = existing {
                if existing_record != record_json || existing_version != version_json {
                    bail!("immutable CVE version conflict")
                }
                let current = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM cve_current WHERE cve_id=$1 AND version_id=$2)", &[&record.id.as_str(), &version.id.as_str()]).map(|row| row.get::<_, bool>(0))?;
                return Ok(CveIngestResult {
                    schema: JSON_VERSION,
                    cve_id: record.id.as_str().to_owned(),
                    version_id: version.id.as_str().to_owned(),
                    revision: version.revision.clone(),
                    inserted: false,
                    current,
                });
            }
            if tx
                .query_one("SELECT id FROM cve_versions WHERE cve_id=$1 AND revision=$2", &[&record.id.as_str(), &version.revision]).map(|row| row.get::<_, String>(0))
                .optional()?
                .is_some()
            {
                bail!("immutable CVE revision conflict")
            }
            tx.execute(
                "INSERT INTO cve_versions(id,cve_id,revision,modified_at,record_json,version_json,observed_at) VALUES ($1,$2,$3,$4,$5,$6,$7)",
                &[&version.id.as_str(), &record.id.as_str(), &version.revision, &version.modified_at.to_rfc3339(), &record_json, &version_json, &record.provenance.observed_at.to_rfc3339()],
            )?;
            for (ordinal, reference) in references.iter().enumerate() {
                let artifact_id: i64 = tx.query_one("SELECT a.id FROM artifacts a JOIN artifact_owners o ON o.artifact_id=a.id WHERE o.source_id=$1 AND o.locator=$2 AND a.sha256=$3", &[&reference.source_id.as_str(), &reference.locator, &reference.content_sha256.as_deref()]).map(|row| row.get(0))?;
                tx.execute(
                    "INSERT INTO cve_version_provenance(version_id,ordinal,source_id,artifact_id,locator,retrieved_at,source_version) VALUES ($1,$2,$3,$4,$5,$6,$7)",
                    &[&version.id.as_str(), &ordinal as i64, &reference.source_id.as_str(), &artifact_id, &reference.locator, &reference.retrieved_at.to_rfc3339(), &reference.source_version],
                )?;
            }
            let current_key = tx
                .query_one("SELECT v.modified_at,v.revision,v.id FROM cve_current c JOIN cve_versions v ON v.id=c.version_id WHERE c.cve_id=$1",
                    &[&record.id.as_str()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
                )
                .optional()?;
            let incoming_key = (
                version.modified_at.to_rfc3339(),
                version.revision.as_str(),
                version.id.as_str(),
            );
            let make_current = current_key.as_ref().is_none_or(|(modified, revision, id)| {
                incoming_key > (modified.clone(), revision.as_str(), id.as_str())
            });
            if make_current {
                tx.execute(
                    "INSERT INTO cve_current(cve_id,version_id) VALUES ($1,$2) ON CONFLICT(cve_id) DO UPDATE SET version_id=excluded.version_id",
                    &[&record.id.as_str(), &version.id.as_str()],
                )?;
            }
            Ok(CveIngestResult {
                schema: JSON_VERSION,
                cve_id: record.id.as_str().to_owned(),
                version_id: version.id.as_str().to_owned(),
                revision: version.revision.clone(),
                inserted: true,
                current: make_current,
            })
        })();
        let result = match outcome {
            Ok(result) => result,
            Err(error) => {
                cleanup_installed_cve_artifacts(&installed_paths, &error)?;
                return Err(error);
            }
        };
        let commit = before_commit(&tx).and_then(|()| tx.commit().map_err(Into::into));
        let Err(error) = commit else {
            return Ok(result);
        };

        // A failed COMMIT is not proof of rollback. The transaction has been
        // consumed (and rusqlite has attempted rollback on drop), so inspect
        // the catalog under a fresh write guard before touching files.
        let probe = CveCommitProbe {
            record,
            version,
            references: &references,
            record_json: &record_json,
            version_json: &version_json,
            installed_paths: &installed_paths,
        };
        match self.reconcile_cve_commit(probe, &error) {
            Ok(CveCommitState::Complete { current }) => Ok(CveIngestResult {
                current,
                ..result
            }),
            Ok(CveCommitState::Absent) => Err(error),
            Ok(CveCommitState::Indeterminate) => Err(error.context(
                "CVE commit outcome is indeterminate; retained newly installed artifacts",
            )),
            Err(probe_error) => Err(error.context(format!(
                "CVE commit outcome could not be verified; retained newly installed artifacts: {probe_error:#}"
            ))),
        }
    }

    fn reconcile_cve_commit(
        &self,
        probe: CveCommitProbe<'_>,
        commit_error: &anyhow::Error,
    ) -> Result<CveCommitState> {
        self.reconcile_cve_commit_with_absent_guard(probe, commit_error, || Ok(()))
    }

    fn reconcile_cve_commit_with_absent_guard<F>(
        &self,
        probe: CveCommitProbe<'_>,
        commit_error: &anyhow::Error,
        before_absent_cleanup: F,
    ) -> Result<CveCommitState>
    where
        F: FnOnce() -> Result<()>,
    {
        let CveCommitProbe {
            record,
            version,
            references,
            record_json,
            version_json,
            installed_paths,
        } = probe;
        let mut c = self.conn().context("open post-commit catalog probe")?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("guard post-commit catalog probe")?;
        let stored = tx
            .query_row(
                "SELECT cve_id,revision,modified_at,record_json,version_json,observed_at FROM cve_versions WHERE id=$1",
                &[&version.id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;

        if let Some(stored) = stored {
            let expected = (
                record.id.as_str(),
                version.revision.as_str(),
                version.modified_at.to_rfc3339(),
                record_json,
                version_json,
                record.provenance.observed_at.to_rfc3339(),
            );
            if (
                stored.0.as_str(),
                stored.1.as_str(),
                stored.2,
                stored.3.as_str(),
                stored.4.as_str(),
                stored.5,
            ) != expected
            {
                return Ok(CveCommitState::Indeterminate);
            }

            let mut statement = tx.prepare(
                "SELECT p.ordinal,p.source_id,p.locator,p.retrieved_at,p.source_version,a.sha256,a.byte_len,a.relative_path,EXISTS(SELECT 1 FROM artifact_owners o WHERE o.source_id=p.source_id AND o.artifact_id=p.artifact_id AND o.locator=p.locator) FROM cve_version_provenance p JOIN artifacts a ON a.id=p.artifact_id WHERE p.version_id=$1 ORDER BY p.ordinal",
            )?;
            let rows = statement
                .query_map(&[&version.id.as_str()], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, bool>(8)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if rows.len() != references.len() {
                return Ok(CveCommitState::Indeterminate);
            }
            for (ordinal, (row, reference)) in rows.iter().zip(references).enumerate() {
                let expected_hash = reference.content_sha256.as_deref().unwrap_or_default();
                let expected_path = format!("sha256/{}/{expected_hash}", &expected_hash[..2]);
                if row.0 != ordinal as i64
                    || row.1 != reference.source_id.as_str()
                    || row.2 != reference.locator
                    || row.3 != reference.retrieved_at.to_rfc3339()
                    || row.4 != reference.source_version
                    || row.5 != expected_hash
                    || row.6 < 0
                    || row.7 != expected_path
                    || !row.8
                {
                    return Ok(CveCommitState::Indeterminate);
                }
                let path = self.artifact_root.join(&row.7);
                let bytes = read_trusted_file(&self.artifact_root, &path, row.6 as u64 + 1)?;
                if bytes.len() as i64 != row.6 || hex(&Sha256::digest(&bytes)) != expected_hash {
                    return Ok(CveCommitState::Indeterminate);
                }
            }
            let current = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM cve_current WHERE cve_id=$1 AND version_id=$2)", &[&record.id.as_str(), &version.id.as_str()]).map(|row| row.get::<_, bool>(0))?;
            return Ok(CveCommitState::Complete { current });
        }

        let conflicting_version: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM cve_versions WHERE cve_id=$1 AND revision=$2)", &[&record.id.as_str(), &version.revision]).map(|row| row.get(0))?;
        let dependent_rows: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM cve_current WHERE version_id=$1) OR EXISTS(SELECT 1 FROM cve_version_provenance WHERE version_id=$1)", &[&version.id.as_str()]).map(|row| row.get(0))?;
        let mut installed_cataloged = false;
        for path in installed_paths {
            let relative = path
                .strip_prefix(&self.artifact_root)
                .context("installed artifact escaped artifact root")?
                .to_string_lossy();
            installed_cataloged |= tx.query_one("SELECT EXISTS(SELECT 1 FROM artifacts WHERE relative_path=$1)", &[&relative.as_ref()]).map(|row| row.get::<_, bool>(0))?;
        }
        let state =
            decide_cve_commit_state(conflicting_version, dependent_rows, installed_cataloged);
        if state == CveCommitState::Absent {
            before_absent_cleanup()?;
            cleanup_installed_cve_artifacts(installed_paths, commit_error)?;
            drop(tx);
        }
        Ok(state)
    }

    pub fn current_cve(&self, cve_id: &str) -> Result<CveCurrent> {
        cve::validate_cve_identifier(cve_id)?;
        let c = self.conn()?;
        let (record_json, version_json) = c
            .query_one("SELECT v.record_json,v.version_json FROM cve_current current JOIN cve_versions v ON v.id=current.version_id WHERE current.cve_id=$1",
                &[&cve_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .context("CVE not found")?;
        Ok(CveCurrent {
            schema: JSON_VERSION,
            record: serde_json::from_str(&record_json).context("invalid stored CVE record")?,
            version: serde_json::from_str(&version_json).context("invalid stored CVE version")?,
        })
    }

    pub fn cve_history(
        &self,
        cve_id: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<CveHistoryPage> {
        cve::validate_cve_identifier(cve_id)?;
        if !(1..=100).contains(&limit) {
            bail!("history limit must be between 1 and 100")
        }
        let cursor = cursor
            .map(|value| decode_history_cursor(value, cve_id))
            .transpose()?;
        let c = self.conn()?;
        let mut statement = c.prepare(
            "SELECT id,revision,modified_at,record_json,version_json FROM cve_versions WHERE cve_id=$1 AND ($2 IS NULL OR modified_at < $2 OR (modified_at = $2 AND (revision < $3 OR (revision = $3 AND id < $4)))) ORDER BY modified_at DESC,revision DESC,id DESC LIMIT $5",
        )?;
        let rows = statement
            .query_map(
                &[&cve_id, &cursor.as_ref().map(|value| value.modified_at.as_str()), &cursor.as_ref().map(|value| value.revision.as_str()), &cursor.as_ref().map(|value| value.id.as_str()), &(limit + 1) as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let has_more = rows.len() > limit;
        let selected = rows.into_iter().take(limit).collect::<Vec<_>>();
        let next_cursor = if has_more {
            selected
                .last()
                .map(|(id, revision, modified_at, _, _)| {
                    encode_history_cursor(cve_id, modified_at, revision, id)
                })
                .transpose()?
        } else {
            None
        };
        let items = selected
            .into_iter()
            .map(|(_, _, _, record_json, version_json)| {
                Ok(CveHistoryItem {
                    record: serde_json::from_str(&record_json)
                        .context("invalid stored CVE record")?,
                    version: serde_json::from_str(&version_json)
                        .context("invalid stored CVE version")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(CveHistoryPage {
            schema: JSON_VERSION,
            cve_id: cve_id.to_owned(),
            items,
            next_cursor,
        })
    }

    /// Export a deterministic, read-only interoperability snapshot.
    pub fn export_interop_snapshot(&self) -> Result<InteropSnapshot> {
        let c = self.conn()?;
        let mut records = Vec::new();
        let mut links = Vec::new();
        let mut provenance = Vec::new();
        let mut diagnostics = Vec::new();
        let mut created_at = String::new();

        let mut st = c.prepare("SELECT id,name,url,enabled,created_at FROM sources ORDER BY id")?;
        for row in st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)? != 0,
                r.get::<_, String>(4)?,
            ))
        })? {
            let (id, name, url, enabled, observed_at) = row?;
            created_at = created_at.max(observed_at.clone());
            records.push(interop_record("source", id.to_string(), observed_at, json!({
                "name": name, "url": redact_url(&url), "user_agent": "<redacted>", "enabled": enabled
            })));
        }

        let mut st = c.prepare("SELECT id,source_id,started_at,finished_at,status,http_status,final_url,error FROM fetch_runs ORDER BY id")?;
        for row in st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
            ))
        })? {
            let (id, source_id, started, finished, status, http_status, final_url, error) = row?;
            created_at = created_at.max(finished.clone().unwrap_or_else(|| started.clone()));
            if let Some(error) = error.as_deref() {
                diagnostics.push(
                    json!({"code": "fetch", "fetch_run_id": id, "message": safe_diagnostic(error)}),
                );
            }
            records.push(interop_record("fetch_run", id.to_string(), started.clone(), json!({
                "source_global_id": format!("mg-brief:source:{source_id}"), "started_at": started,
                "finished_at": finished, "status": status, "http_status": http_status,
                "final_url": final_url.map(|u| redact_url(&u)), "error": error.map(|e| safe_diagnostic(&e))
            })));
            links.push(interop_link(
                "source->fetch_run",
                format!("mg-brief:source:{source_id}"),
                format!("mg-brief:fetch_run:{id}"),
            ));
        }

        let mut st = c.prepare("SELECT id,sha256,byte_len,relative_path,media_type,created_at FROM artifacts ORDER BY sha256")?;
        for row in st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })? {
            let (id, sha, bytes, path, media_type, observed_at) = row?;
            created_at = created_at.max(observed_at.clone());
            records.push(interop_record("artifact", id.to_string(), observed_at, json!({
                "sha256": sha, "bytes": bytes, "path": safe_relative_path(&path)?, "media_type": media_type
            })));
        }

        let mut st = c.prepare("SELECT id,source_id,identity_key,guid,url,title,published_at,first_seen_at FROM feed_items ORDER BY source_id,identity_key")?;
        for row in st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
            ))
        })? {
            let (id, source_id, identity, guid, url, title, published_at, observed_at) = row?;
            created_at = created_at.max(observed_at.clone());
            let global_id = format!("mg-brief:feed_item:{id}");
            records.push(interop_record_with_id(global_id, "feed_item", id.to_string(), observed_at, json!({
                "source_global_id": format!("mg-brief:source:{source_id}"), "identity_key": identity,
                "guid": guid, "url": url.map(|u| redact_url(&u)), "title": title,
                "published_at": published_at
            })));
        }

        let mut st = c.prepare("SELECT id,fetch_run_id,artifact_id,item_id,source_url,fetched_at FROM provenance ORDER BY id")?;
        for row in st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })? {
            let (id, run_id, artifact_id, item_id, source_url, observed_at) = row?;
            created_at = created_at.max(observed_at.clone());
            provenance.push(interop_record(
                "provenance",
                id.to_string(),
                observed_at,
                json!({
                    "fetch_run_global_id": format!("mg-brief:fetch_run:{run_id}"),
                    "artifact_global_id": format!("mg-brief:artifact:{artifact_id}"),
                    "item_global_id": item_id.map(|v| format!("mg-brief:feed_item:{v}")),
                    "source_url": redact_url(&source_url)
                }),
            ));
            links.push(interop_link(
                "fetch_run->artifact",
                format!("mg-brief:fetch_run:{run_id}"),
                format!("mg-brief:artifact:{artifact_id}"),
            ));
            if let Some(item_id) = item_id {
                links.push(interop_link(
                    "fetch_run->feed_item",
                    format!("mg-brief:fetch_run:{run_id}"),
                    format!("mg-brief:feed_item:{item_id}"),
                ));
                let source_id: i64 = c.query_row(
                    "SELECT source_id FROM feed_items WHERE id=$1", &[&item_id]).map(|row| row.get(0))?;
                links.push(interop_link(
                    "source->feed_item",
                    format!("mg-brief:source:{source_id}"),
                    format!("mg-brief:feed_item:{item_id}"),
                ));
            }
            links.push(interop_link(
                "provenance->fetch_run",
                format!("mg-brief:provenance:{id}"),
                format!("mg-brief:fetch_run:{run_id}"),
            ));
            links.push(interop_link(
                "provenance->artifact",
                format!("mg-brief:provenance:{id}"),
                format!("mg-brief:artifact:{artifact_id}"),
            ));
        }
        let mut statement = c.prepare(
            "SELECT current.cve_id,current.version_id,v.record_json,v.observed_at FROM cve_current current JOIN cve_versions v ON v.id=current.version_id ORDER BY current.cve_id",
        )?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })? {
            let (cve_id, version_id, record_json, observed_at) = row?;
            let record: CveRecord =
                serde_json::from_str(&record_json).context("invalid stored CVE record")?;
            created_at = created_at.max(observed_at.clone());
            records.push(interop_record_with_id(
                format!("mg-brief:cve_record:{cve_id}"),
                "cve_record",
                cve_id.clone(),
                observed_at.clone(),
                serde_json::to_value(&record)?,
            ));
            links.push(interop_link(
                "cve_record->current_revision",
                format!("mg-brief:cve_record:{cve_id}"),
                format!("mg-brief:cve_revision:{version_id}"),
            ));
            diagnostics.push(json!({
                "code": "cve_freshness",
                "cve_id": cve_id,
                "status": "not_evaluated",
                "last_observed_at": observed_at
            }));
        }

        let mut statement = c.prepare(
            "SELECT id,cve_id,record_json,version_json,observed_at FROM cve_versions ORDER BY cve_id,modified_at,id",
        )?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })? {
            let (version_id, cve_id, record_json, version_json, observed_at) = row?;
            let record: CveRecord =
                serde_json::from_str(&record_json).context("invalid stored CVE record")?;
            let version: CveVersion =
                serde_json::from_str(&version_json).context("invalid stored CVE version")?;
            records.push(interop_record_with_id(
                format!("mg-brief:cve_revision:{version_id}"),
                "cve_revision",
                version_id.clone(),
                observed_at,
                json!({"record": record, "version": version}),
            ));
            links.push(interop_link(
                "cve_record->revision",
                format!("mg-brief:cve_record:{cve_id}"),
                format!("mg-brief:cve_revision:{version_id}"),
            ));
        }

        let mut statement = c.prepare(
            "SELECT p.version_id,p.ordinal,p.source_id,p.locator,p.retrieved_at,p.source_version,a.id,a.sha256 FROM cve_version_provenance p JOIN artifacts a ON a.id=p.artifact_id ORDER BY p.version_id,p.ordinal",
        )?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
            ))
        })? {
            let (
                version_id,
                ordinal,
                source_id,
                locator,
                retrieved_at,
                source_version,
                artifact_id,
                sha256,
            ) = row?;
            let reference = SourceReference {
                source_id: StableId::new(source_id)?,
                locator,
                content_sha256: Some(sha256),
                retrieved_at: chrono::DateTime::parse_from_rfc3339(&retrieved_at)?
                    .with_timezone(&Utc),
                source_version,
            };
            let provenance_id = format!("{version_id}:{ordinal}");
            provenance.push(interop_record_with_id(
                format!("mg-brief:cve_provenance:{provenance_id}"),
                "cve_provenance",
                provenance_id.clone(),
                retrieved_at,
                serde_json::to_value(&reference)?,
            ));
            links.push(interop_link(
                "cve_revision->provenance",
                format!("mg-brief:cve_revision:{version_id}"),
                format!("mg-brief:cve_provenance:{provenance_id}"),
            ));
            links.push(interop_link(
                "cve_provenance->artifact",
                format!("mg-brief:cve_provenance:{provenance_id}"),
                format!("mg-brief:artifact:{artifact_id}"),
            ));
        }

        links.sort_by(|a, b| {
            (a["type"].as_str(), a["from"].as_str(), a["to"].as_str()).cmp(&(
                b["type"].as_str(),
                b["from"].as_str(),
                b["to"].as_str(),
            ))
        });
        links.dedup();
        let created_at = if created_at.is_empty() {
            "1970-01-01T00:00:00Z".into()
        } else {
            created_at
        };
        let mut snapshot = InteropSnapshot {
            interop_schema: INTEROP_SCHEMA,
            kind: "snapshot",
            producer: InteropProducer {
                app: "mg-brief",
                app_version: env!("CARGO_PKG_VERSION"),
            },
            export_id: String::new(),
            created_at,
            source_revision: String::new(),
            records,
            links,
            provenance,
            diagnostics,
        };
        // Identity covers the complete exported payload, except the two identity
        // fields themselves. This explicit input avoids circular hashing while
        // ensuring provenance, diagnostics, and links cannot be changed silently.
        let revision = interop_revision(&snapshot)?;
        snapshot.export_id = format!("mg-brief:export:{revision}");
        snapshot.source_revision = revision;
        Ok(snapshot)
    }

    pub fn fetch(&self, name: &str, max_bytes: u64, timeout_secs: u64) -> Result<FetchResult> {
        if max_bytes == 0 || max_bytes > usize::MAX as u64 {
            bail!("maximum bytes is invalid")
        }
        if timeout_secs == 0 {
            bail!("timeout is invalid")
        }
        let source = self.source_by_name(name)?;
        if !source.enabled {
            bail!("source is disabled")
        }
        let c = self.conn()?;
        let started = Utc::now().to_rfc3339();
        c.execute(
            "INSERT INTO fetch_runs(source_id,started_at,status) VALUES ($1,$2,'running') RETURNING id",
            &[&source.id, &started],
        )?;
        let run_id: i64 = run_row.get(0);
        match self.fetch_inner(&source, run_id, max_bytes, timeout_secs) {
            Ok((artifact, count, _status, _final_url)) => Ok(FetchResult {
                schema: JSON_VERSION,
                source,
                fetch_run_id: run_id,
                status: "succeeded".into(),
                artifact: Some(artifact),
                items: count,
                error: None,
            }),
            Err(e) => {
                let msg = safe_error(&e);
                c.execute(
                    "UPDATE fetch_runs SET finished_at=$1,status='failed',error=$2 WHERE id=$3",
                    &[&Utc::now().to_rfc3339(), &msg, &run_id],
                )?;
                Ok(FetchResult {
                    schema: JSON_VERSION,
                    source,
                    fetch_run_id: run_id,
                    status: "failed".into(),
                    artifact: None,
                    items: 0,
                    error: Some(msg),
                })
            }
        }
    }

    fn fetch_inner(
        &self,
        source: &Source,
        run: i64,
        max: u64,
        timeout: u64,
    ) -> Result<(Artifact, usize, Option<u16>, String)> {
        let (body, status, final_url, media) = read_source(
            &source.url,
            &source.user_agent,
            max,
            timeout,
            self.trusted_file_root.as_deref(),
        )?;
        let feed = parser::parse(body.as_slice()).context("parse RSS/Atom feed")?;
        let hash = hex(&Sha256::digest(&body));
        let rel = format!("sha256/{}/{}", &hash[..2], hash);
        let path = self.artifact_root.join(&rel);
        let mut installed = false;
        let result = (|| -> Result<(Artifact, usize, Option<u16>, String)> {
            let mut c = self.conn()?;
            // Serialize artifact installation with catalog ownership decisions.
            // A concurrent fetch cannot insert this artifact while this lock is held.
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let outcome = (|| -> Result<(Artifact, usize, Option<u16>, String)> {
                installed = atomic_write_verified(&path, &body, &hash)?;
                let now = Utc::now().to_rfc3339();
                let aid = match tx
                    .query_one("SELECT id FROM artifacts WHERE sha256=$1", &[&hash]).map(|row| row.get::<_, i64>(0))
                    .optional()?
                {
                    Some(id) => id,
                    None => {
                        tx.query_one("INSERT INTO artifacts(sha256,byte_len,relative_path,media_type,created_at) VALUES ($1,$2,$3,$4,$5) RETURNING id", &[&hash, &(body.len() as i64), &rel, &media, &now])?.get::<_, i64>(0)
                    }
                };
                let mut count = 0usize;
                for entry in feed.entries {
                    let guid = nonempty(entry.id.as_str());
                    let link = entry
                        .links
                        .first()
                        .map(|l| l.href.as_str())
                        .and_then(nonempty);
                    let title = entry
                        .title
                        .map(|t| t.content)
                        .unwrap_or_else(|| "(untitled)".into());
                    let identity = identity_key(
                        guid,
                        link,
                        &title,
                        entry.published.map(|d| d.to_rfc3339()).as_deref(),
                    );
                    tx.execute("INSERT INTO feed_items(source_id,identity_key,guid,url,title,published_at,first_seen_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(source_id,identity_key) DO NOTHING", &[&source.id, &identity, &guid, &link, &title, &entry.published.map(|d| d.to_rfc3339()), &now])?;
                    let item_id: i64 = tx.query_row(
                        "SELECT id FROM feed_items WHERE source_id=$1 AND identity_key=$2", &[&source.id, &identity]).map(|row| row.get(0))?;
                    tx.execute("INSERT INTO provenance(fetch_run_id,artifact_id,item_id,source_url,fetched_at) VALUES ($1,$2,$3,$4,$5)", &[&run, &aid, &item_id, &source.url, &now])?;
                    count += 1;
                }
                tx.execute("UPDATE fetch_runs SET finished_at=$1,status='succeeded',http_status=$2,final_url=$3 WHERE id=$4", &[&now, &status, &final_url, &run])?;
                let artifact = Artifact {
                    id: aid,
                    sha256: hash.clone(),
                    bytes: body.len() as u64,
                    path: rel,
                    media_type: media,
                };
                Ok((artifact, count, status, final_url))
            })();
            if outcome.is_err() && installed {
                // Delete only while the IMMEDIATE transaction still owns the
                // SQLite write lock, so no other process can commit a row first.
                let _ = fs::remove_file(&path);
            }
            let result = outcome;
            if result.is_ok() {
                // Once commit is attempted, retain the immutable file on any
                // error: the provider may have committed despite an ambiguous
                // commit result, and an orphan is safer than a dangling row.
                if let Err(error) = tx.commit() {
                    installed = false;
                    return Err(error.into());
                }
            }
            result
        })();
        result
    }
}

#[derive(Debug)]
struct PreparedCveArtifact {
    source_id: String,
    locator: String,
    media_type: String,
    bytes: Vec<u8>,
    sha256: String,
}

fn prepare_cve_artifact(input: &CveArtifactInput) -> Result<PreparedCveArtifact> {
    let locator = StorageLocator::new(&input.locator)?;
    if input.media_type.is_empty()
        || input.media_type.len() > 256
        || input.media_type.chars().any(char::is_control)
    {
        bail!("invalid CVE artifact media type")
    }
    let metadata = fs::symlink_metadata(&input.path).context("inspect CVE artifact")?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("CVE artifact must be a regular non-symlink file")
    }
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&input.path)
            .context("open CVE artifact")?
    };
    #[cfg(not(unix))]
    let mut file = File::open(&input.path).context("open CVE artifact")?;
    if !file.metadata()?.is_file() {
        bail!("CVE artifact must be a regular file")
    }
    let bytes = read_bounded(&mut file, 64 * 1024 * 1024)?;
    let sha256 = hex(&Sha256::digest(&bytes));
    Ok(PreparedCveArtifact {
        source_id: input.source_id.as_str().to_owned(),
        locator: locator.as_str().to_owned(),
        media_type: input.media_type.clone(),
        bytes,
        sha256,
    })
}

fn cve_references(record: &CveRecord, version: &CveVersion) -> Result<Vec<SourceReference>> {
    let mut references = record
        .provenance
        .references
        .iter()
        .chain(&version.provenance.references)
        .cloned()
        .collect::<Vec<_>>();
    for reference in &references {
        StorageLocator::new(&reference.locator)?;
        if reference.content_sha256.is_none() {
            bail!("CVE provenance requires an artifact digest")
        }
    }
    references.sort_by(|left, right| {
        (
            left.source_id.as_str(),
            left.locator.as_str(),
            left.content_sha256.as_deref(),
            left.retrieved_at,
            left.source_version.as_deref(),
        )
            .cmp(&(
                right.source_id.as_str(),
                right.locator.as_str(),
                right.content_sha256.as_deref(),
                right.retrieved_at,
                right.source_version.as_deref(),
            ))
    });
    references.dedup();
    Ok(references)
}

fn verify_cve_artifact(
    tx: &rusqlite::Transaction<'_>,
    root: &Path,
    reference: &SourceReference,
) -> Result<()> {
    let expected = reference
        .content_sha256
        .as_deref()
        .context("CVE provenance requires an artifact digest")?;
    let (relative_path, expected_len): (String, i64) = tx
        .query_one("SELECT a.relative_path,a.byte_len FROM artifacts a JOIN artifact_owners o ON o.artifact_id=a.id WHERE o.source_id=$1 AND o.locator=$2 AND a.sha256=$3",
            &[&reference.source_id.as_str(), &reference.locator, &expected],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("CVE provenance artifact is not owned by this source")?;
    if expected_len < 0 {
        bail!("invalid artifact catalog length")
    }
    let path = root.join(safe_relative_path(&relative_path)?);
    let bytes = read_trusted_file(root, &path, expected_len as u64 + 1)?;
    if bytes.len() as i64 != expected_len || hex(&Sha256::digest(&bytes)) != expected {
        bail!("CVE provenance artifact integrity check failed")
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct HistoryCursor {
    cve_id: String,
    modified_at: String,
    revision: String,
    id: String,
}

fn encode_history_cursor(
    cve_id: &str,
    modified_at: &str,
    revision: &str,
    id: &str,
) -> Result<String> {
    Ok(hex(&serde_json::to_vec(&HistoryCursor {
        cve_id: cve_id.to_owned(),
        modified_at: modified_at.to_owned(),
        revision: revision.to_owned(),
        id: id.to_owned(),
    })?))
}

fn decode_history_cursor(cursor: &str, expected_cve_id: &str) -> Result<HistoryCursor> {
    if cursor.is_empty()
        || cursor.len() > 4096
        || !cursor.len().is_multiple_of(2)
        || !cursor.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("malformed history cursor")
    }
    let bytes = cursor
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let value = std::str::from_utf8(pair).context("malformed history cursor")?;
            u8::from_str_radix(value, 16).context("malformed history cursor")
        })
        .collect::<Result<Vec<_>>>()?;
    let decoded: HistoryCursor =
        serde_json::from_slice(&bytes).context("malformed history cursor")?;
    if decoded.cve_id != expected_cve_id {
        bail!("history cursor belongs to a different CVE");
    }
    chrono::DateTime::parse_from_rfc3339(&decoded.modified_at)
        .context("malformed history cursor")?;
    if decoded.revision.is_empty() || decoded.revision.chars().any(char::is_whitespace) {
        bail!("malformed history cursor");
    }
    StableId::new(decoded.id.clone()).context("malformed history cursor")?;
    Ok(decoded)
}

fn interop_link(kind: &str, from: String, to: String) -> serde_json::Value {
    json!({"type": kind, "from": from, "to": to})
}

fn interop_revision(snapshot: &InteropSnapshot) -> Result<String> {
    let canonical = serde_json::to_vec(&json!({
        "interop_schema": snapshot.interop_schema,
        "kind": snapshot.kind,
        "producer": &snapshot.producer,
        "created_at": &snapshot.created_at,
        "records": &snapshot.records,
        "links": &snapshot.links,
        "provenance": &snapshot.provenance,
        "diagnostics": &snapshot.diagnostics,
    }))?;
    Ok(hex(&Sha256::digest(canonical)))
}

fn interop_record(
    kind: &str,
    local_id: String,
    observed_at: String,
    payload: serde_json::Value,
) -> InteropRecord {
    interop_record_with_id(
        format!("mg-brief:{kind}:{local_id}"),
        kind,
        local_id,
        observed_at,
        payload,
    )
}

fn interop_record_with_id(
    global_id: String,
    kind: &str,
    local_id: String,
    observed_at: String,
    payload: serde_json::Value,
) -> InteropRecord {
    InteropRecord {
        global_id,
        origin: InteropOrigin {
            app: "mg-brief",
            kind: kind.into(),
            local_id,
        },
        revision: 1,
        observed_at,
        payload,
    }
}

fn safe_relative_path(path: &str) -> Result<String> {
    let p = Path::new(path);
    if p.is_absolute()
        || p.components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        bail!("artifact path is not exportable")
    }
    Ok(path.to_owned())
}

fn safe_diagnostic(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if lower.contains("secret") || lower.contains("token") || lower.contains("password") {
        "operation failed".into()
    } else {
        message.replace(['\n', '\r'], " ")
    }
}

fn source_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Source> {
    Ok(Source {
        id: r.get(0)?,
        name: r.get(1)?,
        url: r.get(2)?,
        user_agent: r.get(3)?,
        enabled: r.get::<_, i64>(4)? != 0,
    })
}

/// One embedded schema migration.
///
/// `checksum` pins the exact SQL that was applied. `tables` names what the
/// migration is responsible for creating, so a ledger that records a version
/// whose tables are absent is caught rather than skipped.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
    pub checksum: &'static str,
    pub tables: &'static [&'static str],
}

const M1_CATALOG_FOUNDATION: &str = "CREATE TABLE sources (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,name text NOT NULL UNIQUE,url text NOT NULL UNIQUE,user_agent text NOT NULL,enabled boolean NOT NULL DEFAULT true,created_at text NOT NULL); CREATE TABLE fetch_runs (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,source_id bigint NOT NULL REFERENCES sources(id),started_at text NOT NULL,finished_at text,status text NOT NULL,http_status bigint,final_url text,error text); CREATE TABLE artifacts (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,sha256 text NOT NULL UNIQUE,byte_len bigint NOT NULL,relative_path text NOT NULL UNIQUE,media_type text NOT NULL,created_at text NOT NULL); CREATE TABLE feed_items (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,source_id bigint NOT NULL REFERENCES sources(id),identity_key text NOT NULL,guid text,url text,title text NOT NULL,published_at text,first_seen_at text NOT NULL,UNIQUE(source_id,identity_key)); CREATE TABLE provenance (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,fetch_run_id bigint NOT NULL REFERENCES fetch_runs(id),artifact_id bigint NOT NULL REFERENCES artifacts(id),item_id bigint REFERENCES feed_items(id),source_url text NOT NULL,fetched_at text NOT NULL);";
const M2_FEED_ITEM_INDEX: &str = "CREATE INDEX IF NOT EXISTS idx_feed_items_source_identity ON feed_items(source_id, identity_key);";
const M3_CVE_INTELLIGENCE: &str = "CREATE TABLE artifact_owners (source_id text NOT NULL,artifact_id bigint NOT NULL REFERENCES artifacts(id),locator text NOT NULL,PRIMARY KEY(source_id,artifact_id,locator)); CREATE TABLE cve_versions (id text PRIMARY KEY,cve_id text NOT NULL,revision text NOT NULL,modified_at text NOT NULL,record_json text NOT NULL,version_json text NOT NULL,observed_at text NOT NULL,UNIQUE(cve_id,revision)); CREATE TABLE cve_current (cve_id text PRIMARY KEY,version_id text NOT NULL UNIQUE REFERENCES cve_versions(id)); CREATE TABLE cve_version_provenance (version_id text NOT NULL REFERENCES cve_versions(id),ordinal bigint NOT NULL,source_id text NOT NULL,artifact_id bigint NOT NULL REFERENCES artifacts(id),locator text NOT NULL,retrieved_at text NOT NULL,source_version text,PRIMARY KEY(version_id,ordinal)); CREATE INDEX idx_cve_history ON cve_versions(cve_id,modified_at DESC,id DESC);";
const M4_ASSET_INVENTORY: &str = "CREATE TABLE asset_records (id text PRIMARY KEY,created_at text NOT NULL,asset_json text NOT NULL); CREATE TABLE asset_observations (id text PRIMARY KEY,asset_id text NOT NULL REFERENCES asset_records(id),observed_at text NOT NULL,corrects_observation_id text REFERENCES asset_observations(id),observation_json text NOT NULL); CREATE INDEX idx_asset_observations_asset_time ON asset_observations(asset_id,observed_at DESC,id DESC);";

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "catalog_foundation",
        sql: M1_CATALOG_FOUNDATION,
        checksum: "cd85c78cd10c29921ffcac1868b849debf06531f7a852e5b88208dbc69171068",
        tables: &[
            "sources",
            "fetch_runs",
            "artifacts",
            "feed_items",
            "provenance",
        ],
    },
    Migration {
        version: 2,
        name: "feed_item_index",
        sql: M2_FEED_ITEM_INDEX,
        checksum: "9c691f5ef305bfe22095bdc84ce48eddf835651f3ab5a018aca19e7413cbf36f",
        tables: &[],
    },
    Migration {
        version: 3,
        name: "cve_intelligence",
        sql: M3_CVE_INTELLIGENCE,
        checksum: "91e1a000e191c32631d37f9a638954ba0ab58e845f5e43d93cd11efb441ff47c",
        tables: &[
            "artifact_owners",
            "cve_versions",
            "cve_current",
            "cve_version_provenance",
        ],
    },
    Migration {
        version: 4,
        name: "asset_inventory",
        sql: M4_ASSET_INVENTORY,
        checksum: "bbdab23d4663aaeb4281fa2597d1552ce31d425825e2e975315cd7830148a942",
        tables: &["asset_records", "asset_observations"],
    },
];

/// State of one embedded migration against a live catalog.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MigrationState {
    pub version: i64,
    pub name: &'static str,
    pub applied: bool,
}

fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Read migration state without opening a write transaction or applying anything.
pub fn migration_status(c: &Connection) -> Result<Vec<MigrationState>> {
    let exists: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name = 'schema_migrations')", []).map(|row| row.get(0))?;
    let applied: Vec<i64> = if exists {
        let mut st = c.prepare("SELECT version FROM schema_migrations ORDER BY version")?;
        let rows = st.query_map([], |r| r.get::<_, i64>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    Ok(MIGRATIONS
        .iter()
        .map(|m| MigrationState {
            version: m.version,
            name: m.name,
            applied: applied.contains(&m.version),
        })
        .collect())
}

/// Refuse an embedded migration whose SQL no longer matches its recorded checksum.
///
/// Without this the checksum is decoration: editing a migration's SQL and its
/// checksum together would still let a rewritten migration reach a database.
fn validate_embedded_migrations() -> Result<()> {
    for migration in MIGRATIONS {
        if sha256_hex(migration.sql) != migration.checksum {
            bail!(
                "embedded schema migration {} ('{}') does not match its checksum",
                migration.version,
                migration.name
            )
        }
    }
    Ok(())
}

fn migrate(c: &mut Connection) -> Result<()> {
    validate_embedded_migrations()?;
    let latest = MIGRATIONS.last().map_or(0, |m| m.version);
    // Keep ledger discovery and every migration in one write transaction. In
    // particular, do not inspect the ledger before acquiring SQLite's write
    // lock: two first-time opens could otherwise both observe an empty ledger
    // and race while creating the migration tables.
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.batch_execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);",
    )?;
    // The ledger predates checksums. Add the column rather than rewriting the
    // table, so an existing catalog keeps its history.
    let has_checksum: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = 'schema_migrations' \
           AND column_name = 'checksum')", []).map(|row| row.get(0))?;
    if !has_checksum {
        tx.batch_execute("ALTER TABLE schema_migrations ADD COLUMN checksum text")?;
    }

    let recorded = {
        let mut st =
            tx.prepare("SELECT version, checksum FROM schema_migrations ORDER BY version")?;
        let rows = st.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (index, (version, _)) in recorded.iter().enumerate() {
        let expected = index as i64 + 1;
        if *version != expected || *version > latest {
            bail!("schema migration ledger is inconsistent")
        }
    }

    verify_recorded_migrations(&tx, &recorded)?;

    let mut current = recorded.last().map(|(v, _)| *v).unwrap_or(0);
    while current < latest {
        let next = current + 1;
        let migration = MIGRATIONS
            .iter()
            .find(|m| m.version == next)
            .expect("embedded migrations are contiguous");
        tx.batch_execute(migration.sql)?;
        tx.execute(
            "INSERT INTO schema_migrations(version, checksum) VALUES ($1, $2)",
            &[&next, &migration.checksum],
        )?;
        current = next;
    }
    tx.commit()?;
    Ok(())
}

/// Refuse a catalog whose recorded migrations no longer match the embedded ones.
///
/// A migration edited after it was applied is invisible to a version-only
/// ledger: the runner skips it and the new statements never run, leaving a
/// database that reports itself current while missing tables. Compare the
/// recorded checksum, and where a legacy row carries none, compare the live
/// schema instead.
fn verify_recorded_migrations(
    tx: &rusqlite::Transaction<'_>,
    recorded: &[(i64, Option<String>)],
) -> Result<()> {
    for (version, checksum) in recorded {
        let Some(migration) = MIGRATIONS.iter().find(|m| m.version == *version) else {
            bail!("catalog records unknown schema migration {version}")
        };
        if let Some(recorded_checksum) = checksum {
            if recorded_checksum != migration.checksum {
                bail!(
                    "schema migration {version} ('{}') was changed after it was applied; \
                     this catalog cannot be upgraded in place",
                    migration.name
                )
            }
            continue;
        }
        // Legacy row with no checksum: the live tables are the only evidence.
        for table in migration.tables {
            let present: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM information_schema.tables \
                 WHERE table_schema = current_schema() AND table_name = $1)", &[&table]).map(|row| row.get(0))?;
            if !present {
                bail!(
                    "schema migration {version} ('{}') is recorded but table '{table}' is missing; \
                     this catalog predates a change to that migration",
                    migration.name
                )
            }
        }
        tx.execute(
            "UPDATE schema_migrations SET checksum=$2 WHERE version=$1",
            &[&version, &migration.checksum],
        )?;
    }
    Ok(())
}

fn recover_stale_runs(c: &Connection) -> Result<()> {
    let cutoff = (Utc::now() - STALE_RUN_AGE).to_rfc3339();
    c.execute(
        "UPDATE fetch_runs SET finished_at=$1,status='failed',error='fetch interrupted' WHERE status='running' AND started_at < $2",
        &[&Utc::now().to_rfc3339(), &cutoff],
    )?;
    Ok(())
}

fn validate_url(raw: &str) -> Result<Url> {
    let u = Url::parse(raw).context("source URL must be an absolute URL")?;
    validate_parsed_url(u)
}

fn validate_parsed_url(u: Url) -> Result<Url> {
    if !matches!(u.scheme(), "http" | "https" | "file") {
        bail!("source URL scheme is not allowed")
    }
    if u.username() != "" || u.password().is_some() {
        bail!("source URL userinfo is not allowed")
    }
    if u.host_str().is_none() && u.scheme() != "file" {
        bail!("source URL host is required")
    }
    Ok(u)
}

fn read_source(
    source: &str,
    ua: &str,
    max: u64,
    timeout: u64,
    file_root: Option<&Path>,
) -> Result<(Vec<u8>, Option<u16>, String, String)> {
    let mut u = validate_url(source)?;
    if u.scheme() == "file" {
        let root = file_root.context("file sources require trusted fixture mode")?;
        let p = u
            .to_file_path()
            .map_err(|_| anyhow::anyhow!("invalid file source"))?;
        return read_trusted_file(root, &p, max)
            .map(|b| (b, None, redact_url(source), "application/rss+xml".into()));
    }
    for _ in 0..=MAX_REDIRECTS {
        let address = validate_network_target(&u)?;
        let client = Client::builder()
            .redirect(Policy::none())
            // SSRF validation and pinned resolution must not be bypassed by a proxy.
            .no_proxy()
            .timeout(Duration::from_secs(timeout))
            .user_agent(ua)
            // Pin the request to the address that was checked above. This prevents
            // reqwest's later DNS lookup from changing the security decision
            .resolve(
                u.host_str().context("source URL host is required")?,
                address,
            )
            .build()?;
        let r = client.get(u.clone()).send()?;
        if r.status().is_redirection() {
            let location = r
                .headers()
                .get(reqwest::header::LOCATION)
                .context("redirect missing location")?
                .to_str()
                .context("invalid redirect location")?;
            u = validate_parsed_url(u.join(location)?)?;
            if u.scheme() != "http" && u.scheme() != "https" {
                bail!("redirect scheme is not allowed")
            }
            continue;
        }
        return read_response(r, max, redact_url(u.as_str()));
    }
    bail!("too many redirects")
}

fn validate_network_target(u: &Url) -> Result<std::net::SocketAddr> {
    let host = u.host_str().context("source URL host is required")?;
    let port = u
        .port_or_known_default()
        .context("source URL port is invalid")?;
    let mut addrs = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![std::net::SocketAddr::new(ip, port)]
    } else {
        (host, port).to_socket_addrs()?.collect()
    };
    addrs.retain(|a| !forbidden_ip(a.ip()));
    addrs
        .into_iter()
        .next()
        .context("source host has no allowed address")
}

fn forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_multicast()
                || v.is_unspecified()
                || (v.octets()[0] == 169 && v.octets()[1] == 254)
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_multicast()
                || v.is_unspecified()
                || v.is_unique_local()
                || v.is_unicast_link_local()
                || v.to_ipv4().is_some()
        }
    }
}

#[cfg(unix)]
fn read_trusted_file(root: &Path, path: &Path, max: u64) -> Result<Vec<u8>> {
    use rustix::fs::{openat, Mode, OFlags, CWD};

    let root = fs::canonicalize(root)?;
    let relative = path
        .strip_prefix(&root)
        .map_err(|_| anyhow::anyhow!("file source is outside trusted fixture root"))?;
    let components = relative.components().collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("file source contains a non-normal path component")
    }
    let mut dir = openat(
        CWD,
        &root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let mut components = components.into_iter().peekable();
    while let Some(component) = components.next() {
        let name = component
            .as_os_str()
            .to_str()
            .context("invalid file source path")?;
        if components.peek().is_some() {
            dir = openat(
                &dir,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                Mode::empty(),
            )?;
        } else {
            let fd = openat(&dir, name, OFlags::RDONLY | OFlags::NOFOLLOW, Mode::empty())?;
            let mut file = File::from(fd);
            if !file.metadata()?.is_file() {
                bail!("file source must name a regular file")
            }
            return read_bounded(&mut file, max);
        }
    }
    bail!("file source must name a regular file")
}

#[cfg(not(unix))]
fn read_trusted_file(root: &Path, path: &Path, max: u64) -> Result<Vec<u8>> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.starts_with(root) {
        bail!("file source is outside trusted fixture root")
    }
    let mut file = File::open(canonical)?;
    read_bounded(&mut file, max)
}

fn read_response(
    r: Response,
    max: u64,
    final_url: String,
) -> Result<(Vec<u8>, Option<u16>, String, String)> {
    let status = r.status().as_u16();
    let r = r.error_for_status()?;
    if r.content_length().is_some_and(|n| n > max) {
        bail!("response exceeds configured maximum")
    }
    let media = r
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/rss+xml")
        .split(';')
        .next()
        .unwrap_or("application/rss+xml")
        .to_owned();
    let mut out = Vec::new();
    r.take(max.checked_add(1).context("maximum bytes overflow")?)
        .read_to_end(&mut out)?;
    if out.len() as u64 > max {
        bail!("response exceeds configured maximum")
    }
    Ok((out, Some(status), final_url, media))
}

fn read_bounded(r: &mut impl Read, max: u64) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    r.take(max.checked_add(1).context("maximum bytes overflow")?)
        .read_to_end(&mut b)?;
    if b.len() as u64 > max {
        bail!("source exceeds configured maximum")
    }
    Ok(b)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CveCommitState {
    Complete { current: bool },
    Absent,
    Indeterminate,
}

#[derive(Clone, Copy)]
struct CveCommitProbe<'a> {
    record: &'a CveRecord,
    version: &'a CveVersion,
    references: &'a [SourceReference],
    record_json: &'a str,
    version_json: &'a str,
    installed_paths: &'a [PathBuf],
}

fn decide_cve_commit_state(
    conflicting_version: bool,
    dependent_rows: bool,
    installed_cataloged: bool,
) -> CveCommitState {
    if conflicting_version || dependent_rows || installed_cataloged {
        CveCommitState::Indeterminate
    } else {
        CveCommitState::Absent
    }
}

fn cleanup_installed_cve_artifacts(paths: &[PathBuf], error: &anyhow::Error) -> Result<()> {
    for path in paths {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {}
            Err(cleanup_error) => {
                return Err(cleanup_error).with_context(|| {
                    format!(
                        "clean up CVE artifact after ingest failure: {} ({error:#})",
                        path.display()
                    )
                });
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn atomic_write_verified(path: &Path, body: &[u8], expected_hash: &str) -> Result<bool> {
    atomic_write_verified_unix(path, body, expected_hash)
}

#[cfg(not(unix))]
fn atomic_write_verified(path: &Path, body: &[u8], expected_hash: &str) -> Result<bool> {
    atomic_write_verified_portable(path, body, expected_hash)
}

#[cfg(unix)]
fn atomic_write_verified_unix(path: &Path, body: &[u8], expected_hash: &str) -> Result<bool> {
    use rustix::fs::{openat, Mode, OFlags, CWD};
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    let root = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .context("artifact path")?;
    let namespace = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .context("artifact namespace")?;
    let shard = path
        .parent()
        .context("artifact path")?
        .file_name()
        .context("artifact shard")?;
    let name = path.file_name().context("artifact filename")?;
    let root_fd = openat(
        CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let namespace = open_or_create_artifact_dir(&root_fd, namespace)?;
    let shard = open_or_create_artifact_dir(&namespace, shard)?;
    let shard_fd = shard.as_raw_fd();
    let name = CString::new(name.to_str().context("invalid artifact filename")?)?;

    if let Ok(fd) = openat(
        &shard,
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        let mut file = std::fs::File::from(fd);
        let (hash, len) = digest_reader(&mut file)?;
        if hash != expected_hash || len != body.len() as u64 {
            bail!("existing artifact integrity check failed")
        }
        return Ok(false);
    }

    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let tmp_name = CString::new(format!(
        ".{}.tmp-{}-{}",
        name.to_string_lossy(),
        std::process::id(),
        unique
    ))?;
    let tmp = openat(
        &shard,
        &tmp_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )?;
    let mut temp = std::fs::File::from(tmp);
    temp.write_all(body)?;
    temp.sync_all()?;
    drop(temp);

    let rename = unsafe {
        // SAFETY: all pointers are NUL-free CString paths and valid while the syscall runs
        libc::renameat2(
            shard_fd,
            tmp_name.as_ptr(),
            shard_fd,
            name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rename == 0 {
        if let Err(error) = sync_directory_fd(shard_fd) {
            let _ = unsafe {
                // SAFETY: shard_fd is an open directory and name is a valid
                // NUL-free name for the just-installed artifact.
                libc::unlinkat(shard_fd, name.as_ptr(), 0)
            };
            return Err(error.context("sync artifact directory"));
        }
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    let _ = unsafe {
        // SAFETY: shard_fd is an open directory and tmp_name is a valid NUL-free name
        libc::unlinkat(shard_fd, tmp_name.as_ptr(), 0)
    };
    if error.kind() != std::io::ErrorKind::AlreadyExists {
        return Err(error.into());
    }
    let fd = openat(
        &shard,
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let mut file = std::fs::File::from(fd);
    let (hash, len) = digest_reader(&mut file)?;
    if hash != expected_hash || len != body.len() as u64 {
        bail!("existing artifact integrity check failed")
    }
    Ok(false)
}

#[cfg(unix)]
fn sync_directory_fd(fd: std::os::unix::io::RawFd) -> Result<()> {
    let result = unsafe {
        // SAFETY: callers pass the live descriptor of an open directory.
        libc::fsync(fd)
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(unix)]
fn open_or_create_artifact_dir<Fd: std::os::fd::AsFd>(
    parent: &Fd,
    name: &std::ffi::OsStr,
) -> Result<std::os::fd::OwnedFd> {
    use rustix::fs::{mkdirat, openat, Mode, OFlags};
    match mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )?)
}

#[cfg(not(unix))]
struct TempArtifact {
    path: PathBuf,
}

#[cfg(not(unix))]
impl Drop for TempArtifact {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(not(unix))]
fn atomic_write_verified_portable(path: &Path, body: &[u8], expected_hash: &str) -> Result<bool> {
    use std::fs::OpenOptions;

    let parent = path.parent().context("artifact path")?;
    fs::create_dir_all(parent)?;
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            bail!("artifact path is not a regular file")
        }
        let (hash, len) = digest_file(path)?;
        if hash != expected_hash || len != body.len() as u64 {
            bail!("existing artifact integrity check failed")
        }
        return Ok(false);
    }
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let tmp = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .context("artifact filename")?
            .to_string_lossy(),
        std::process::id(),
        unique
    ));
    let mut temp = TempArtifact { path: tmp.clone() };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(&tmp)?;
    f.write_all(body)?;
    f.sync_all()?;
    match fs::rename(&tmp, path) {
        Ok(()) => {
            if let Err(error) = sync_artifact_directory(parent) {
                let _ = fs::remove_file(path);
                return Err(error.context("sync artifact directory"));
            }
            temp.path = PathBuf::new();
            Ok(true)
        }
        Err(_) => {
            if let Ok(meta) = fs::symlink_metadata(path) {
                if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                    bail!("artifact path is not a regular file")
                }
                let (hash, len) = digest_file(path)?;
                if hash != expected_hash || len != body.len() as u64 {
                    bail!("existing artifact integrity check failed")
                }
                Ok(false)
            } else {
                bail!("artifact install failed")
            }
        }
    }
}

fn digest_reader(reader: &mut impl Read) -> Result<(String, u64)> {
    let mut h = Sha256::new();
    let mut len = 0u64;
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        len = len
            .checked_add(n as u64)
            .context("artifact length overflow")?;
    }
    Ok((hex(&h.finalize()), len))
}

#[cfg(not(unix))]
fn digest_file(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path)?;
    digest_reader(&mut file)
}

#[cfg(windows)]
fn sync_artifact_directory(_parent: &Path) -> Result<()> {
    // Windows does not expose a portable directory fsync through std::fs.
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn sync_artifact_directory(parent: &Path) -> Result<()> {
    File::open(parent).and_then(|directory| directory.sync_all())?;
    Ok(())
}

fn identity_key(
    guid: Option<&str>,
    link: Option<&str>,
    title: &str,
    published: Option<&str>,
) -> String {
    match (guid, link) {
        (Some(guid), _) => format!("guid\u{1f}{guid}"),
        (None, Some(link)) => format!("link\u{1f}{link}"),
        (None, None) => format!("fallback\u{1f}{title}\u{1f}{}", published.unwrap_or("")),
    }
}
fn nonempty(s: &str) -> Option<&str> {
    (!s.trim().is_empty()).then_some(s)
}
fn redact_url(raw: &str) -> String {
    Url::parse(raw)
        .map(|mut u| {
            let _ = u.set_password(None);
            let _ = u.set_username("");
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        })
        .unwrap_or_else(|_| "<invalid-url>".into())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn safe_error(e: &anyhow::Error) -> String {
    let text = e.to_string().to_ascii_lowercase();
    if text.contains("exceeds configured maximum") || text.contains("source exceeds configured") {
        "source exceeds configured maximum".into()
    } else if text.contains("parse rss/atom") {
        "feed parse failed".into()
    } else {
        "fetch failed".into()
    }
}

use std::io::Write;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cve::{Confidence, Provenance};
    use chrono::{DateTime, TimeZone};
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write;

    fn cve_fixture(
        artifact_path: &Path,
        seconds: i64,
        revision: &str,
        version_id: &str,
        source_id: &str,
        locator: &str,
    ) -> (CveRecord, CveVersion, CveArtifactInput) {
        let modified_at = Utc.timestamp_opt(1_704_067_200 + seconds, 0).unwrap();
        let sha256 = hex(&Sha256::digest(fs::read(artifact_path).unwrap()));
        let reference = SourceReference {
            source_id: StableId::new(source_id).unwrap(),
            locator: locator.into(),
            content_sha256: Some(sha256),
            retrieved_at: modified_at,
            source_version: Some(revision.into()),
        };
        let provenance = Provenance {
            references: vec![reference],
            confidence: Confidence::Exact,
            observed_at: modified_at,
        };
        let record = CveRecord {
            id: StableId::new("CVE-2024-1234").unwrap(),
            aliases: vec![],
            descriptions: BTreeMap::from([("en".into(), format!("revision {revision}"))]),
            cna: Some("example".into()),
            published_at: Some(DateTime::UNIX_EPOCH),
            modified_at,
            withdrawn_at: None,
            provenance: provenance.clone(),
        };
        let version = CveVersion {
            id: StableId::new(version_id).unwrap(),
            cve_id: record.id.clone(),
            revision: revision.into(),
            modified_at,
            fields: BTreeMap::from([("state".into(), json!("published"))]),
            provenance,
        };
        let artifact = CveArtifactInput {
            source_id: StableId::new(source_id).unwrap(),
            locator: locator.into(),
            path: artifact_path.to_owned(),
            media_type: "application/json".into(),
        };
        (record, version, artifact)
    }
    #[test]
    fn file_fetch_is_immutable_and_provenant() -> Result<()> {
        let d = tempfile::tempdir()?;
        let root = d.path().join("fixtures");
        fs::create_dir_all(&root)?;
        let feed = root.join("feed.xml");
        let mut f = fs::File::create(&feed)?;
        writeln!(f, "<rss version=\"2.0\"><channel><title>T</title><link>https://example.test</link><description>D</description><item><title>Hello</title><link>https://example.test/a</link></item></channel></rss>")?;
        let s = Store::open_with_trusted_file_root(
            d.path().join("db.sqlite"),
            d.path().join("artifacts"),
            &root,
        )?;
        let feed_url = Url::from_file_path(&feed).unwrap();
        let src = s.register("test", feed_url.as_str(), None)?;
        let a = s.fetch(&src.name, 1024, 1)?;
        assert_eq!(a.status, "succeeded");
        let ar = a.artifact.unwrap();
        assert_eq!(
            ar.bytes,
            fs::metadata(s.artifact_root.join(&ar.path))?.len()
        );
        let b = s.fetch("test", 1024, 1)?;
        assert_eq!(ar.sha256, b.artifact.unwrap().sha256);
        let snapshot = s.export_interop_snapshot()?;
        let link_types: Vec<&str> = snapshot
            .links
            .iter()
            .filter_map(|link| link["type"].as_str())
            .collect();
        assert!(link_types.contains(&"source->fetch_run"));
        assert!(link_types.contains(&"fetch_run->artifact"));
        assert!(link_types.contains(&"fetch_run->feed_item"));
        assert!(link_types.contains(&"source->feed_item"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn trusted_file_rejects_parent_components_after_strip_prefix() -> Result<()> {
        let d = tempfile::tempdir()?;
        let root = d.path().join("fixtures");
        fs::create_dir_all(&root)?;
        let outside = d.path().join("outside.xml");
        fs::write(&outside, b"outside")?;
        let traversal = root.join("nested/../..").join("outside.xml");
        assert!(read_trusted_file(&root, &traversal, 1024).is_err());
        Ok(())
    }

    #[test]
    fn disabled_source_is_rejected() -> Result<()> {
        let d = tempfile::tempdir()?;
        let s = Store::open(d.path().join("db"), d.path().join("a"))?;
        s.register("x", "https://example.test", None)?;
        s.set_enabled("x", false)?;
        assert!(s.fetch("x", 10, 1).is_err());
        Ok(())
    }
    #[test]
    fn userinfo_and_private_targets_are_rejected() {
        assert!(validate_url("https://u:p@example.test").is_err());
        assert!(validate_network_target(&Url::parse("http://127.0.0.1").unwrap()).is_err());
    }
    #[test]
    fn mapped_and_link_local_ipv6_targets_are_rejected() {
        assert!(forbidden_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(forbidden_ip("fe80::1".parse().unwrap()));
        assert!(
            validate_network_target(&Url::parse("http://[::ffff:127.0.0.1]").unwrap()).is_err()
        );
        assert!(validate_network_target(&Url::parse("http://[fe80::1]").unwrap()).is_err());
    }

    #[test]
    fn migration_gap_is_rejected() -> Result<()> {
        let d = tempfile::tempdir()?;
        let db = d.path().join("db.sqlite");
        let c = Connection::open(&db)?;
        c.batch_execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY); INSERT INTO schema_migrations(version) VALUES (2);")?;
        drop(c);
        assert!(Store::open(&db, d.path().join("artifacts")).is_err());
        Ok(())
    }

    #[test]
    fn concurrent_first_opens_serialize_migration_initialization() -> Result<()> {
        let d = tempfile::tempdir()?;
        let db = d.path().join("db.sqlite");
        let artifacts = d.path().join("artifacts");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let barrier = std::sync::Arc::clone(&barrier);
            let db = db.clone();
            let artifacts = artifacts.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                Store::open(db, artifacts).map(|_| ())
            }));
        }
        for handle in handles {
            handle.join().expect("migration worker panicked")?;
        }
        let c = Connection::open(db)?;
        let versions: Vec<i64> = c
            .prepare("SELECT version FROM schema_migrations ORDER BY version")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(versions, vec![1, 2, 3, 4]);
        Ok(())
    }

    #[test]
    fn stale_running_runs_are_recovered_on_open_without_interrupting_active_runs() -> Result<()> {
        let d = tempfile::tempdir()?;
        let db = d.path().join("db.sqlite");
        let store = Store::open(&db, d.path().join("artifacts"))?;
        let c = store.conn()?;
        c.execute(
            "INSERT INTO sources(name,url,user_agent,created_at) VALUES ('x','https://example.test','ua','now')",
            [],
        )?;
        let old = (Utc::now() - ChronoDuration::hours(2)).to_rfc3339();
        c.execute(
            "INSERT INTO fetch_runs(source_id,started_at,status) VALUES (1,$1,'running')",
            &[&old],
        )?;
        let recent = (Utc::now() - ChronoDuration::minutes(5)).to_rfc3339();
        c.execute(
            "INSERT INTO fetch_runs(source_id,started_at,status) VALUES (1,$1,'running')",
            &[&recent],
        )?;
        drop(c);

        let reopened = Store::open(&db, d.path().join("artifacts"))?;
        let c = reopened.conn()?;
        let statuses: Vec<String> = c
            .prepare("SELECT status FROM fetch_runs ORDER BY id")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(statuses, vec!["failed", "running"]);
        Ok(())
    }

    #[test]
    fn symlinked_artifact_directory_is_rejected() -> Result<()> {
        let d = tempfile::tempdir()?;
        let real = d.path().join("real");
        let link = d.path().join("link");
        fs::create_dir(&real)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link)?;
        #[cfg(unix)]
        assert!(atomic_write_verified(
            &link.join("x/y"),
            b"x",
            "2d711642b726b04401627ca9fbac32f5da7e0e5e6f7b4e8f4b6e6b5f9f1c1a6b"
        )
        .is_err());
        Ok(())
    }
    #[test]
    fn existing_corrupt_artifact_is_rejected() -> Result<()> {
        let d = tempfile::tempdir()?;
        let root = d.path().join("a");
        let p = root.join("sha256/aa/hash");
        fs::create_dir_all(p.parent().unwrap())?;
        fs::write(&p, b"bad")?;
        assert!(atomic_write_verified(
            &p,
            b"good",
            "770e607624d689265ca6c44884d0807d9b054d23c2b6f8f70a1e54f7e5e6f3a2"
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn interop_empty_snapshot_is_stable() -> Result<()> {
        let d = tempfile::tempdir()?;
        let store = Store::open(d.path().join("db.sqlite"), d.path().join("artifacts"))?;
        let first = serde_json::to_string(&store.export_interop_snapshot()?)?;
        let second = serde_json::to_string(&store.export_interop_snapshot()?)?;
        assert_eq!(first, second);
        let snapshot = store.export_interop_snapshot()?;
        assert_eq!(snapshot.interop_schema, "mg.interop/1");
        assert_eq!(snapshot.kind, "snapshot");
        assert!(snapshot.records.is_empty());
        assert!(snapshot.provenance.is_empty());
        let mut changed = snapshot.clone();
        changed.links.push(interop_link(
            "source->fetch_run",
            "mg-brief:source:1".into(),
            "mg-brief:fetch_run:1".into(),
        ));
        assert_ne!(snapshot.source_revision, interop_revision(&changed)?);
        let mut changed = snapshot.clone();
        changed.provenance.push(interop_record(
            "provenance",
            "1".into(),
            "1970-01-01T00:00:00Z".into(),
            json!({"source_url": "https://example.test"}),
        ));
        assert_ne!(snapshot.source_revision, interop_revision(&changed)?);
        let mut changed = snapshot.clone();
        changed.diagnostics.push(json!({"code": "test"}));
        assert_ne!(snapshot.source_revision, interop_revision(&changed)?);
        Ok(())
    }

    #[test]
    fn interop_catalog_contains_identities_and_redacts_sensitive_fields() -> Result<()> {
        let d = tempfile::tempdir()?;
        let store = Store::open(d.path().join("db.sqlite"), d.path().join("artifacts"))?;
        store.register(
            "private",
            "https://example.test/feed?token=abc",
            Some("Agent secret"),
        )?;
        let snapshot = store.export_interop_snapshot()?;
        let encoded = serde_json::to_string(&snapshot)?;
        assert!(encoded.contains("mg-brief:source:1"));
        assert!(encoded.contains("<redacted>"));
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("token=abc"));
        assert!(!encoded.contains(&store.db_path.to_string_lossy().to_string()));
        assert!(!encoded.contains(&store.artifact_root.to_string_lossy().to_string()));
        let source = snapshot
            .records
            .iter()
            .find(|r| r.origin.kind == "source")
            .unwrap();
        assert_eq!(source.origin.local_id, "1");
        assert_eq!(source.revision, 1);
        Ok(())
    }

    #[test]
    fn cve_ingest_is_immutable_ordered_paginated_and_exported() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let artifact_path = directory.path().join("raw.json");
        fs::write(&artifact_path, br#"{"source":"nvd"}"#)?;
        let store = Store::open(
            directory.path().join("db.sqlite"),
            directory.path().join("artifacts"),
        )?;
        let baseline = store.export_interop_snapshot()?;
        let (new_record, new_version, artifact) = cve_fixture(
            &artifact_path,
            20,
            "2",
            "CVE-2024-1234:nvd:2",
            "nvd",
            "/private/nvd/raw.json",
        );
        let first = store.ingest_cve(&new_record, &new_version, std::slice::from_ref(&artifact))?;
        assert!(first.inserted);
        assert!(first.current);
        let replay = store.ingest_cve(&new_record, &new_version, &[])?;
        assert!(!replay.inserted);
        assert!(replay.current);

        let (old_record, old_version, _) = cve_fixture(
            &artifact_path,
            10,
            "1",
            "CVE-2024-1234:nvd:1",
            "nvd",
            "/private/nvd/raw.json",
        );
        let old = store.ingest_cve(&old_record, &old_version, &[])?;
        assert!(old.inserted);
        assert!(!old.current);
        assert_eq!(store.current_cve("CVE-2024-1234")?.version.revision, "2");

        let page_one = store.cve_history("CVE-2024-1234", 1, None)?;
        assert_eq!(page_one.items.len(), 1);
        assert_eq!(page_one.items[0].version.revision, "2");
        assert_eq!(page_one.items[0].record.descriptions["en"], "revision 2");
        let page_two = store.cve_history("CVE-2024-1234", 1, page_one.next_cursor.as_deref())?;
        assert_eq!(page_two.items.len(), 1);
        assert_eq!(page_two.items[0].version.revision, "1");
        assert_eq!(page_two.items[0].record.descriptions["en"], "revision 1");
        assert!(page_two.next_cursor.is_none());
        assert!(store.cve_history("CVE-2024-1234", 1, Some("nope")).is_err());

        let first_export = store.export_interop_snapshot()?;
        let second_export = store.export_interop_snapshot()?;
        assert_ne!(baseline.source_revision, first_export.source_revision);
        assert_ne!(baseline.export_id, first_export.export_id);
        assert_eq!(
            serde_json::to_vec(&first_export)?,
            serde_json::to_vec(&second_export)?
        );
        let encoded = serde_json::to_string(&first_export)?;
        assert!(encoded.contains("cve_record"));
        assert!(encoded.contains("cve_revision"));
        assert!(encoded.contains("cve_freshness"));
        let historical_descriptions = first_export
            .records
            .iter()
            .filter(|record| record.origin.kind == "cve_revision")
            .map(|record| {
                record.payload["record"]["descriptions"]["en"]
                    .as_str()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(historical_descriptions, vec!["revision 1", "revision 2"]);
        assert!(first_export
            .records
            .iter()
            .filter(|record| record.origin.kind == "cve_revision")
            .all(|record| record.payload["version"]["revision"].is_string()));
        assert!(!encoded.contains("/private/nvd/raw.json"));
        assert!(!encoded.contains(&artifact_path.to_string_lossy().to_string()));
        Ok(())
    }

    #[test]
    fn cve_ingest_rejects_unsafe_missing_mismatched_and_cross_source_artifacts() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let artifact_path = directory.path().join("raw.json");
        fs::write(&artifact_path, b"authoritative")?;
        let store = Store::open(
            directory.path().join("db.sqlite"),
            directory.path().join("artifacts"),
        )?;
        let (record, version, artifact) = cve_fixture(
            &artifact_path,
            0,
            "1",
            "CVE-2024-1234:nvd:1",
            "nvd",
            "https://private.example.test/nvd.json",
        );
        assert!(store.ingest_cve(&record, &version, &[]).is_err());

        let mut wrong_digest_record = record.clone();
        wrong_digest_record.provenance.references[0].content_sha256 = Some("0".repeat(64));
        let mut wrong_digest_version = version.clone();
        wrong_digest_version.provenance = wrong_digest_record.provenance.clone();
        assert!(store
            .ingest_cve(
                &wrong_digest_record,
                &wrong_digest_version,
                std::slice::from_ref(&artifact)
            )
            .is_err());

        let mut cross_source = artifact.clone();
        cross_source.source_id = StableId::new("vendor").unwrap();
        assert!(store
            .ingest_cve(&record, &version, &[cross_source])
            .is_err());

        let mut unsafe_record = record.clone();
        unsafe_record.provenance.references[0].locator =
            "https://user:password@example.test/nvd.json".into();
        let mut unsafe_version = version.clone();
        unsafe_version.provenance = unsafe_record.provenance.clone();
        assert!(store
            .ingest_cve(
                &unsafe_record,
                &unsafe_version,
                std::slice::from_ref(&artifact),
            )
            .is_err());

        let signed_locator =
            "https://private.example.test/nvd.json?X-Amz-Credential=access&X-Amz-Signature=deadbeef";
        let mut signed_record = record.clone();
        signed_record.provenance.references[0].locator = signed_locator.into();
        let mut signed_version = version.clone();
        signed_version.provenance = signed_record.provenance.clone();
        let mut signed_artifact = artifact.clone();
        signed_artifact.locator = signed_locator.into();
        assert!(store
            .ingest_cve(&signed_record, &signed_version, &[signed_artifact])
            .is_err());

        let accepted = store.ingest_cve(&record, &version, &[artifact])?;
        assert!(accepted.inserted);
        let stored_path = directory
            .path()
            .join("artifacts/sha256")
            .join(
                &record.provenance.references[0]
                    .content_sha256
                    .as_ref()
                    .unwrap()[..2],
            )
            .join(
                record.provenance.references[0]
                    .content_sha256
                    .as_ref()
                    .unwrap(),
            );
        fs::write(stored_path, b"tampered")?;
        assert!(store.ingest_cve(&record, &version, &[]).is_err());
        Ok(())
    }

    #[test]
    fn cve_conflict_rolls_back_revision_and_provenance_rows() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let artifact_path = directory.path().join("raw.json");
        fs::write(&artifact_path, b"authority")?;
        let store = Store::open(
            directory.path().join("db.sqlite"),
            directory.path().join("artifacts"),
        )?;
        let (record, version, artifact) = cve_fixture(
            &artifact_path,
            0,
            "1",
            "CVE-2024-1234:nvd:1",
            "nvd",
            "private/nvd.json",
        );
        store.ingest_cve(&record, &version, std::slice::from_ref(&artifact))?;
        let mut conflict = version.clone();
        conflict.id = StableId::new("CVE-2024-1234:nvd:conflict").unwrap();
        assert!(store.ingest_cve(&record, &conflict, &[artifact]).is_err());
        let connection = store.conn()?;
        let versions: i64 =
            connection.query_one("SELECT COUNT(*) FROM cve_versions", []).map(|row| row.get(0))?;
        let provenance: i64 =
            connection.query_one("SELECT COUNT(*) FROM cve_version_provenance", [], |row| {
                row.get(0)
            })?;
        assert_eq!(versions, 1);
        assert_eq!(provenance, 1);
        Ok(())
    }

    #[test]
    fn cve_commit_failure_removes_new_artifacts_but_preserves_reused_files() -> Result<()> {
        for reused in [false, true] {
            let directory = tempfile::tempdir()?;
            let artifact_path = directory.path().join("raw.json");
            fs::write(&artifact_path, b"authority")?;
            let store = Store::open(
                directory.path().join("db.sqlite"),
                directory.path().join("artifacts"),
            )?;
            let (record, version, artifact) = cve_fixture(
                &artifact_path,
                0,
                "1",
                "CVE-2024-1234:nvd:1",
                "nvd",
                "private/nvd.json",
            );
            let digest = record.provenance.references[0]
                .content_sha256
                .as_deref()
                .unwrap();
            let installed_path = store
                .artifact_root
                .join(format!("sha256/{}/{digest}", &digest[..2]));
            if reused {
                assert!(atomic_write_verified(
                    &installed_path,
                    b"authority",
                    digest
                )?);
            }

            let mut read_lock = None;
            let error = store
                .ingest_cve_with_before_commit(
                    &record,
                    &version,
                    std::slice::from_ref(&artifact),
                    |transaction| {
                        assert!(installed_path.exists());
                        transaction.busy_timeout(Duration::ZERO)?;
                        let connection = store.conn()?;
                        connection.batch_execute("BEGIN DEFERRED")?;
                        connection.query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| {
                            row.get::<_, i64>(0)
                        })?;
                        read_lock = Some(connection);
                        Ok(())
                    },
                )
                .unwrap_err();
            assert!(error.to_string().contains("database is locked"));
            assert_eq!(installed_path.exists(), reused);

            drop(read_lock.take());
            let connection = store.conn()?;
            for table in ["artifacts", "artifact_owners", "cve_versions"] {
                let count: i64 =
                    connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
                assert_eq!(count, 0, "unexpected rows in {table}");
            }
        }
        Ok(())
    }

    #[test]
    fn cve_commit_error_returns_success_when_complete_state_committed() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let artifact_path = directory.path().join("raw.json");
        fs::write(&artifact_path, b"authority")?;
        let store = Store::open(
            directory.path().join("db.sqlite"),
            directory.path().join("artifacts"),
        )?;
        let (record, version, artifact) = cve_fixture(
            &artifact_path,
            0,
            "1",
            "CVE-2024-1234:nvd:1",
            "nvd",
            "private/nvd.json",
        );
        let digest = record.provenance.references[0]
            .content_sha256
            .as_deref()
            .unwrap();
        let installed_path = store
            .artifact_root
            .join(format!("sha256/{}/{digest}", &digest[..2]));

        let result =
            store.ingest_cve_with_before_commit(&record, &version, &[artifact], |transaction| {
                // Deterministically model a provider that committed but then
                // reported an error to its caller.
                transaction.batch_execute("COMMIT")?;
                bail!("simulated ambiguous commit result")
            })?;

        assert!(result.inserted);
        assert!(result.current);
        assert!(installed_path.exists());
        assert_eq!(
            store.current_cve(record.id.as_str())?.version.id,
            version.id
        );
        let connection = store.conn()?;
        let versions: i64 =
            connection.query_row("SELECT COUNT(*) FROM cve_versions", []).map(|row| row.get(0))?;
        let provenance: i64 =
            connection.query_one("SELECT COUNT(*) FROM cve_version_provenance", [], |row| {
                row.get(0)
            })?;
        assert_eq!(versions, 1);
        assert_eq!(provenance, 1);
        Ok(())
    }

    #[test]
    fn cve_commit_failure_retains_file_when_artifact_was_already_cataloged() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let artifact_path = directory.path().join("raw.json");
        fs::write(&artifact_path, b"authority")?;
        let store = Store::open(
            directory.path().join("db.sqlite"),
            directory.path().join("artifacts"),
        )?;
        let (record, version, artifact) = cve_fixture(
            &artifact_path,
            0,
            "1",
            "CVE-2024-1234:nvd:1",
            "nvd",
            "private/nvd.json",
        );
        let digest = record.provenance.references[0]
            .content_sha256
            .as_deref()
            .unwrap();
        let relative_path = format!("sha256/{}/{digest}", &digest[..2]);
        let installed_path = store.artifact_root.join(&relative_path);
        store.conn()?.execute(
            "INSERT INTO artifacts(sha256,byte_len,relative_path,media_type,created_at) VALUES ($1,$2,$3,$4,$5)",
            &[&digest, &9_i64, &relative_path, &"application/json", &record.modified_at.to_rfc3339()],
        )?;
        assert!(!installed_path.exists());

        let mut read_lock = None;
        let error = store
            .ingest_cve_with_before_commit(&record, &version, &[artifact], |transaction| {
                transaction.busy_timeout(Duration::ZERO)?;
                let connection = store.conn()?;
                connection.batch_execute("BEGIN DEFERRED")?;
                connection.query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| {
                    row.get::<_, i64>(0)
                })?;
                read_lock = Some(connection);
                Ok(())
            })
            .unwrap_err();

        assert!(error.to_string().contains("indeterminate"));
        assert!(installed_path.exists());
        drop(read_lock.take());
        let connection = store.conn()?;
        let versions: i64 =
            connection.query_row("SELECT COUNT(*) FROM cve_versions", []).map(|row| row.get(0))?;
        let artifacts: i64 =
            connection.query_one("SELECT COUNT(*) FROM artifacts", []).map(|row| row.get(0))?;
        assert_eq!(versions, 0);
        assert_eq!(artifacts, 1);
        Ok(())
    }

    #[test]
    fn cve_absent_reconciliation_guards_cleanup_from_concurrent_catalog_writes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let artifact_path = directory.path().join("raw.json");
        fs::write(&artifact_path, b"authority")?;
        let store = Store::open(
            directory.path().join("db.sqlite"),
            directory.path().join("artifacts"),
        )?;
        let journal = store.conn()?;
        journal.pragma_update(None, "journal_mode", "WAL")?;
        drop(journal);

        let (record, version, _) = cve_fixture(
            &artifact_path,
            0,
            "1",
            "CVE-2024-1234:nvd:1",
            "nvd",
            "private/nvd.json",
        );
        let digest = record.provenance.references[0]
            .content_sha256
            .as_deref()
            .unwrap();
        let relative_path = format!("sha256/{}/{digest}", &digest[..2]);
        let installed_path = store.artifact_root.join(&relative_path);
        assert!(atomic_write_verified(
            &installed_path,
            b"authority",
            digest
        )?);

        let references = cve_references(&record, &version)?;
        let record_json = cve::cve_record_storage_json(&record)?;
        let version_json = cve::cve_version_storage_json(&version)?;
        let commit_error = anyhow::anyhow!("simulated failed commit");
        let writer = store.conn()?;
        writer.busy_timeout(Duration::ZERO)?;
        let probe = CveCommitProbe {
            record: &record,
            version: &version,
            references: &references,
            record_json: &record_json,
            version_json: &version_json,
            installed_paths: std::slice::from_ref(&installed_path),
        };
        let state = store.reconcile_cve_commit_with_absent_guard(
            probe,
            &commit_error,
            || {
                assert!(installed_path.exists());
                let write_error = writer
                    .execute(
                        "INSERT INTO artifacts(sha256,byte_len,relative_path,media_type,created_at) VALUES ($1,$2,$3,$4,$5)",
                        &[&digest, &9_i64, &relative_path, &"application/json", &record.modified_at.to_rfc3339()],
                    )
                    .unwrap_err();
                assert!(write_error.to_string().contains("database is locked"));
                Ok(())
            },
        )?;

        assert_eq!(state, CveCommitState::Absent);
        assert!(!installed_path.exists());
        writer.execute(
            "INSERT INTO artifacts(sha256,byte_len,relative_path,media_type,created_at) VALUES ($1,$2,$3,$4,$5)",
            &[&digest, &9_i64, &relative_path, &"application/json", &record.modified_at.to_rfc3339()],
        )?;
        let cataloged: bool = writer.query_one("SELECT EXISTS(SELECT 1 FROM artifacts WHERE sha256=$1)", &[&digest]).map(|row| row.get(0))?;
        assert!(cataloged);
        Ok(())
    }

    #[test]
    fn cve_absent_commit_state_requires_every_catalog_signal_to_be_absent() {
        assert_eq!(
            decide_cve_commit_state(false, false, false),
            CveCommitState::Absent
        );
        for signals in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ] {
            assert_eq!(
                decide_cve_commit_state(signals.0, signals.1, signals.2),
                CveCommitState::Indeterminate
            );
        }
    }

    #[test]
    fn failed_cve_ingest_removes_new_artifacts_but_preserves_reused_files() -> Result<()> {
        for reused in [false, true] {
            let directory = tempfile::tempdir()?;
            let artifact_path = directory.path().join("raw.json");
            fs::write(&artifact_path, b"authority")?;
            let store = Store::open(
                directory.path().join("db.sqlite"),
                directory.path().join("artifacts"),
            )?;
            let (mut record, mut version, artifact) = cve_fixture(
                &artifact_path,
                0,
                "1",
                "CVE-2024-1234:nvd:1",
                "nvd",
                "private/nvd.json",
            );
            let digest = record.provenance.references[0]
                .content_sha256
                .as_deref()
                .unwrap();
            let installed_path = store
                .artifact_root
                .join(format!("sha256/{}/{digest}", &digest[..2]));
            if reused {
                assert!(atomic_write_verified(
                    &installed_path,
                    b"authority",
                    digest
                )?);
            }
            let missing = SourceReference {
                source_id: StableId::new("nvd")?,
                locator: "private/missing.json".into(),
                content_sha256: Some("f".repeat(64)),
                retrieved_at: record.modified_at,
                source_version: Some("1".into()),
            };
            record.provenance.references.push(missing.clone());
            version.provenance.references.push(missing);

            assert!(store.ingest_cve(&record, &version, &[artifact]).is_err());
            assert_eq!(installed_path.exists(), reused);
            let connection = store.conn()?;
            for table in ["artifacts", "artifact_owners", "cve_versions"] {
                let count: i64 =
                    connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
                assert_eq!(count, 0, "unexpected rows in {table}");
            }
        }
        Ok(())
    }
}
