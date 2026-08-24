pub mod cve;

use anyhow::{bail, Context, Result};
use chrono::{Duration as ChronoDuration, Utc};
use feed_rs::parser;
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;
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
    pub db_path: PathBuf,
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

    fn conn(&self) -> Result<Connection> {
        let c = Connection::open(&self.db_path).context("open catalog")?;
        c.busy_timeout(Duration::from_secs(5))
            .context("configure catalog lock")?;
        c.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(c)
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
        c.execute("INSERT INTO sources(name,url,user_agent,created_at) VALUES (?1,?2,?3,?4) ON CONFLICT(name) DO UPDATE SET url=excluded.url,user_agent=excluded.user_agent,enabled=1", params![name, parsed.as_str(), ua, Utc::now().to_rfc3339()])?;
        self.source_by_name(name)
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        let c = self.conn()?;
        if c.execute(
            "UPDATE sources SET enabled=?1 WHERE name=?2",
            params![enabled as i64, name],
        )? != 1
        {
            bail!("source not found")
        }
        Ok(())
    }

    pub fn source_by_name(&self, name: &str) -> Result<Source> {
        let c = self.conn()?;
        c.query_row(
            "SELECT id,name,url,user_agent,enabled FROM sources WHERE name=?1",
            params![name],
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
                    "SELECT source_id FROM feed_items WHERE id=?1",
                    params![item_id],
                    |r| r.get(0),
                )?;
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
            "INSERT INTO fetch_runs(source_id,started_at,status) VALUES (?1,?2,'running')",
            params![source.id, started],
        )?;
        let run_id = c.last_insert_rowid();
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
                    "UPDATE fetch_runs SET finished_at=?1,status='failed',error=?2 WHERE id=?3",
                    params![Utc::now().to_rfc3339(), msg, run_id],
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
                    .query_row(
                        "SELECT id FROM artifacts WHERE sha256=?1",
                        params![hash],
                        |r| r.get::<_, i64>(0),
                    )
                    .optional()?
                {
                    Some(id) => id,
                    None => {
                        tx.execute("INSERT INTO artifacts(sha256,byte_len,relative_path,media_type,created_at) VALUES (?1,?2,?3,?4,?5)", params![hash, body.len() as i64, rel, media, now])?;
                        tx.last_insert_rowid()
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
                    tx.execute("INSERT INTO feed_items(source_id,identity_key,guid,url,title,published_at,first_seen_at) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(source_id,identity_key) DO NOTHING", params![source.id, identity, guid, link, title, entry.published.map(|d| d.to_rfc3339()), now])?;
                    let item_id: i64 = tx.query_row(
                        "SELECT id FROM feed_items WHERE source_id=?1 AND identity_key=?2",
                        params![source.id, identity],
                        |r| r.get(0),
                    )?;
                    tx.execute("INSERT INTO provenance(fetch_run_id,artifact_id,item_id,source_url,fetched_at) VALUES (?1,?2,?3,?4,?5)", params![run, aid, item_id, source.url, now])?;
                    count += 1;
                }
                tx.execute("UPDATE fetch_runs SET finished_at=?1,status='succeeded',http_status=?2,final_url=?3 WHERE id=?4", params![now, status, final_url, run])?;
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

fn migrate(c: &mut Connection) -> Result<()> {
    const LATEST: i64 = 2;
    // Keep ledger discovery and every migration in one write transaction. In
    // particular, do not inspect the ledger before acquiring SQLite's write
    // lock: two first-time opens could otherwise both observe an empty ledger
    // and race while creating the migration tables.
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);",
    )?;
    let versions = {
        let mut st = tx.prepare("SELECT version FROM schema_migrations ORDER BY version")?;
        let rows = st.query_map([], |r| r.get::<_, i64>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (index, version) in versions.iter().enumerate() {
        let expected = index as i64 + 1;
        if *version != expected || *version > LATEST {
            bail!("schema migration ledger is inconsistent")
        }
    }
    let mut current = versions.last().copied().unwrap_or(0);
    while current < LATEST {
        let next = current + 1;
        match next {
            1 => tx.execute_batch("CREATE TABLE sources (id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,url TEXT NOT NULL UNIQUE,user_agent TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL); CREATE TABLE fetch_runs (id INTEGER PRIMARY KEY,source_id INTEGER NOT NULL REFERENCES sources(id),started_at TEXT NOT NULL,finished_at TEXT,status TEXT NOT NULL,http_status INTEGER,final_url TEXT,error TEXT); CREATE TABLE artifacts (id INTEGER PRIMARY KEY,sha256 TEXT NOT NULL UNIQUE,byte_len INTEGER NOT NULL,relative_path TEXT NOT NULL UNIQUE,media_type TEXT NOT NULL,created_at TEXT NOT NULL); CREATE TABLE feed_items (id INTEGER PRIMARY KEY,source_id INTEGER NOT NULL REFERENCES sources(id),identity_key TEXT NOT NULL,guid TEXT,url TEXT,title TEXT NOT NULL,published_at TEXT,first_seen_at TEXT NOT NULL,UNIQUE(source_id,identity_key)); CREATE TABLE provenance (id INTEGER PRIMARY KEY,fetch_run_id INTEGER NOT NULL REFERENCES fetch_runs(id),artifact_id INTEGER NOT NULL REFERENCES artifacts(id),item_id INTEGER REFERENCES feed_items(id),source_url TEXT NOT NULL,fetched_at TEXT NOT NULL);")?,
            2 => tx.execute_batch("CREATE INDEX IF NOT EXISTS idx_feed_items_source_identity ON feed_items(source_id, identity_key);")?,
            _ => unreachable!(),
        }
        tx.execute(
            "INSERT INTO schema_migrations(version) VALUES (?1)",
            params![next],
        )?;
        current = next;
    }
    tx.commit()?;
    Ok(())
}

fn recover_stale_runs(c: &Connection) -> Result<()> {
    let cutoff = (Utc::now() - STALE_RUN_AGE).to_rfc3339();
    c.execute(
        "UPDATE fetch_runs SET finished_at=?1,status='failed',error='fetch interrupted' WHERE status='running' AND started_at < ?2",
        params![Utc::now().to_rfc3339(), cutoff],
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
    use std::fs;
    use std::io::Write;
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
        c.execute_batch("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY); INSERT INTO schema_migrations(version) VALUES (2);")?;
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
        assert_eq!(versions, vec![1, 2]);
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
            "INSERT INTO fetch_runs(source_id,started_at,status) VALUES (1,?1,'running')",
            params![old],
        )?;
        let recent = (Utc::now() - ChronoDuration::minutes(5)).to_rfc3339();
        c.execute(
            "INSERT INTO fetch_runs(source_id,started_at,status) VALUES (1,?1,'running')",
            params![recent],
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
}
