use anyhow::{Context, Result};
use postgres::{Client, NoTls};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct PostgresStore {
    pub database_url: String,
    pub artifact_root: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PostgresFeedItem {
    pub id: i64,
    pub source_id: i64,
    pub identity_key: String,
    pub guid: Option<String>,
    pub url: Option<String>,
    pub title: String,
    pub published_at: Option<String>,
    pub first_seen_at: String,
}
#[derive(Debug, Clone)]
pub struct FeedItemInput<'a> {
    pub source_id: i64,
    pub identity_key: &'a str,
    pub guid: Option<&'a str>,
    pub url: Option<&'a str>,
    pub title: &'a str,
    pub published_at: Option<&'a str>,
}
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
}

const M1: &str = r#"
CREATE TABLE sources (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 name TEXT NOT NULL UNIQUE, url TEXT NOT NULL UNIQUE,
 user_agent TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE fetch_runs (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 source_id BIGINT NOT NULL REFERENCES sources(id), started_at TIMESTAMPTZ NOT NULL,
 finished_at TIMESTAMPTZ, status TEXT NOT NULL, http_status INTEGER,
 final_url TEXT, error TEXT
);
CREATE TABLE artifacts (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 sha256 TEXT NOT NULL UNIQUE, byte_len BIGINT NOT NULL,
 relative_path TEXT NOT NULL UNIQUE, media_type TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE feed_items (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 source_id BIGINT NOT NULL REFERENCES sources(id), identity_key TEXT NOT NULL,
 guid TEXT, url TEXT, title TEXT NOT NULL, published_at TIMESTAMPTZ,
 first_seen_at TIMESTAMPTZ NOT NULL, UNIQUE(source_id, identity_key)
);
CREATE TABLE provenance (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 fetch_run_id BIGINT NOT NULL REFERENCES fetch_runs(id),
 artifact_id BIGINT NOT NULL REFERENCES artifacts(id),
 item_id BIGINT REFERENCES feed_items(id), source_url TEXT NOT NULL,
 fetched_at TIMESTAMPTZ NOT NULL
);
"#;
const M2: &str = "CREATE INDEX IF NOT EXISTS idx_feed_items_source_identity ON feed_items(source_id, identity_key);";
const M3: &str = r#"
CREATE TABLE artifact_owners (
 source_id TEXT NOT NULL, artifact_id BIGINT NOT NULL REFERENCES artifacts(id),
 locator TEXT NOT NULL, PRIMARY KEY(source_id, artifact_id, locator)
);
CREATE TABLE cve_versions (
 id TEXT PRIMARY KEY, cve_id TEXT NOT NULL, revision TEXT NOT NULL,
 modified_at TIMESTAMPTZ NOT NULL, record_json JSONB NOT NULL,
 version_json JSONB NOT NULL, observed_at TIMESTAMPTZ NOT NULL,
 UNIQUE(cve_id, revision)
);
CREATE TABLE cve_current (
 cve_id TEXT PRIMARY KEY, version_id TEXT NOT NULL UNIQUE REFERENCES cve_versions(id)
);
CREATE TABLE cve_version_provenance (
 version_id TEXT NOT NULL REFERENCES cve_versions(id), ordinal INTEGER NOT NULL,
 source_id TEXT NOT NULL, artifact_id BIGINT NOT NULL REFERENCES artifacts(id),
 locator TEXT NOT NULL, retrieved_at TIMESTAMPTZ NOT NULL, source_version TEXT,
 PRIMARY KEY(version_id, ordinal)
);
CREATE INDEX idx_cve_history ON cve_versions(cve_id, modified_at DESC, id DESC);
"#;
const M4: &str = r#"
CREATE TABLE asset_records (
 id TEXT PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL, asset_json JSONB NOT NULL
);
CREATE TABLE asset_observations (
 id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES asset_records(id),
 observed_at TIMESTAMPTZ NOT NULL, corrects_observation_id TEXT REFERENCES asset_observations(id),
 observation_json JSONB NOT NULL
);
CREATE INDEX idx_asset_observations_asset_time
 ON asset_observations(asset_id, observed_at DESC, id DESC);
"#;

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "catalog_foundation",
        sql: M1,
    },
    Migration {
        version: 2,
        name: "feed_item_index",
        sql: M2,
    },
    Migration {
        version: 3,
        name: "cve_intelligence",
        sql: M3,
    },
    Migration {
        version: 4,
        name: "asset_inventory",
        sql: M4,
    },
];

fn migration_checksum(sql: &str) -> String {
    Sha256::digest(sql.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_fetch_status(status: &str) -> Result<()> {
    if !matches!(status, "succeeded" | "failed") {
        anyhow::bail!("fetch run status must be succeeded or failed");
    }
    Ok(())
}

fn validate_persisted_versions(persisted: &[i64], max_version: usize) -> Result<()> {
    for (index, version) in persisted.iter().enumerate() {
        if *version != (index as i64) + 1 || *version > max_version as i64 {
            anyhow::bail!("PostgreSQL migration ledger has a gap or unknown version");
        }
    }
    Ok(())
}

impl PostgresStore {
    pub fn open(
        database_url: impl Into<String>,
        artifact_root: impl Into<PathBuf>,
    ) -> Result<Self> {
        let artifact_root = artifact_root.into();
        fs::create_dir_all(&artifact_root).context("create artifact root")?;
        let store = Self {
            database_url: database_url.into(),
            artifact_root,
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn connect(&self) -> Result<Client> {
        Client::connect(&self.database_url, NoTls).context("connect to PostgreSQL catalog")
    }

    pub fn migrate(&self) -> Result<()> {
        let mut client = self.connect()?;
        let mut tx = client.transaction().context("begin catalog migration")?;
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&6_851_863_988_i64])?;
        tx.batch_execute("CREATE TABLE IF NOT EXISTS mg_brief_schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL)")?;
        let persisted: Vec<i64> = tx
            .query(
                "SELECT version FROM mg_brief_schema_migrations ORDER BY version",
                &[],
            )?
            .iter()
            .map(|row| row.get(0))
            .collect();
        validate_persisted_versions(&persisted, MIGRATIONS.len())?;
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            if migration.version != (index as i64) + 1 {
                anyhow::bail!("PostgreSQL migrations are not contiguous");
            }
            let checksum = migration_checksum(migration.sql);
            let applied = tx.query_opt(
                "SELECT name, checksum FROM mg_brief_schema_migrations WHERE version=$1",
                &[&migration.version],
            )?;
            if let Some(row) = applied {
                let name: String = row.get(0);
                let applied_checksum: String = row.get(1);
                if name != migration.name || applied_checksum != checksum {
                    anyhow::bail!("migration {} checksum or name mismatch", migration.version);
                }
                continue;
            }
            tx.batch_execute(migration.sql)
                .with_context(|| format!("apply PostgreSQL migration {}", migration.version))?;
            tx.execute(
                "INSERT INTO mg_brief_schema_migrations(version,name,checksum) VALUES ($1,$2,$3)",
                &[&migration.version, &migration.name, &checksum],
            )?;
        }
        tx.commit().context("commit catalog migration")?;
        Ok(())
    }

    pub fn register(
        &self,
        name: &str,
        source_url: &str,
        user_agent: Option<&str>,
    ) -> Result<crate::Source> {
        let parsed = crate::validate_url(source_url)?;
        if parsed.scheme() == "file" {
            anyhow::bail!("file sources require trusted fixture mode");
        }
        let ua = user_agent.unwrap_or(crate::DEFAULT_USER_AGENT);
        if ua.contains(['\r', '\n']) || ua.len() > 512 {
            anyhow::bail!("user-agent is invalid");
        }
        let mut client = self.connect()?;
        let row = client.query_one(
            "INSERT INTO sources(name,url,user_agent,created_at) VALUES ($1,$2,$3,CURRENT_TIMESTAMP) ON CONFLICT(name) DO UPDATE SET url=EXCLUDED.url,user_agent=EXCLUDED.user_agent,enabled=TRUE RETURNING id,name,url,user_agent,enabled",
            &[&name, &parsed.as_str(), &ua],
        )?;
        Ok(crate::Source {
            id: row.get(0),
            name: row.get(1),
            url: row.get(2),
            user_agent: row.get(3),
            enabled: row.get(4),
        })
    }

    pub fn list_sources(&self) -> Result<Vec<crate::Source>> {
        let mut client = self.connect()?;
        let rows = client.query(
            "SELECT id,name,url,user_agent,enabled FROM sources ORDER BY id",
            &[],
        )?;
        Ok(rows
            .into_iter()
            .map(|row| crate::Source {
                id: row.get(0),
                name: row.get(1),
                url: row.get(2),
                user_agent: row.get(3),
                enabled: row.get(4),
            })
            .collect())
    }

    pub fn start_fetch_run(&self, source_id: i64) -> Result<i64> {
        let mut client = self.connect()?;
        let row = client.query_one(
            "INSERT INTO fetch_runs(source_id,started_at,status) VALUES ($1,CURRENT_TIMESTAMP,'running') RETURNING id",
            &[&source_id],
        )?;
        Ok(row.get(0))
    }

    pub fn finish_fetch_run(
        &self,
        fetch_run_id: i64,
        status: &str,
        http_status: Option<i32>,
        final_url: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        validate_fetch_status(status)?;
        let mut client = self.connect()?;
        let updated = client.execute(
            "UPDATE fetch_runs SET finished_at=CURRENT_TIMESTAMP,status=$1,http_status=$2,final_url=$3,error=$4 WHERE id=$5 AND status='running'",
            &[&status, &http_status, &final_url, &error, &fetch_run_id],
        )?;
        if updated != 1 {
            anyhow::bail!("fetch run is missing or already terminal");
        }
        Ok(())
    }

    pub fn upsert_feed_item(&self, item: FeedItemInput<'_>) -> Result<i64> {
        let mut client = self.connect()?;
        let row = client.query_one(
            "INSERT INTO feed_items(source_id,identity_key,guid,url,title,published_at,first_seen_at) VALUES ($1,$2,$3,$4,$5,CAST($6 AS TIMESTAMPTZ),CURRENT_TIMESTAMP) ON CONFLICT(source_id,identity_key) DO UPDATE SET guid=EXCLUDED.guid,url=EXCLUDED.url,title=EXCLUDED.title,published_at=EXCLUDED.published_at RETURNING id",
            &[&item.source_id, &item.identity_key, &item.guid, &item.url, &item.title, &item.published_at],
        )?;
        Ok(row.get(0))
    }

    pub fn list_feed_items(
        &self,
        source_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<PostgresFeedItem>> {
        if !(1..=10_000).contains(&limit) {
            anyhow::bail!("feed item limit must be between 1 and 10000");
        }
        let mut client = self.connect()?;
        let rows = if let Some(source_id) = source_id {
            client.query(
                "SELECT id,source_id,identity_key,guid,url,title,published_at::TEXT,first_seen_at::TEXT FROM feed_items WHERE source_id=$1 ORDER BY source_id,identity_key LIMIT $2",
                &[&source_id, &limit],
            )?
        } else {
            client.query(
                "SELECT id,source_id,identity_key,guid,url,title,published_at::TEXT,first_seen_at::TEXT FROM feed_items ORDER BY source_id,identity_key LIMIT $1",
                &[&limit],
            )?
        };
        Ok(rows
            .into_iter()
            .map(|row| PostgresFeedItem {
                id: row.get(0),
                source_id: row.get(1),
                identity_key: row.get(2),
                guid: row.get(3),
                url: row.get(4),
                title: row.get(5),
                published_at: row.get(6),
                first_seen_at: row.get(7),
            })
            .collect())
    }

    pub fn record_provenance(
        &self,
        fetch_run_id: i64,
        artifact_id: i64,
        item_id: Option<i64>,
        source_url: &str,
    ) -> Result<i64> {
        let mut client = self.connect()?;
        let row = client.query_one(
            "INSERT INTO provenance(fetch_run_id,artifact_id,item_id,source_url,fetched_at) VALUES ($1,$2,$3,$4,CURRENT_TIMESTAMP) RETURNING id",
            &[&fetch_run_id, &artifact_id, &item_id, &source_url],
        )?;
        Ok(row.get(0))
    }

    pub fn upsert_artifact(
        &self,
        sha256: &str,
        byte_len: i64,
        relative_path: &str,
        media_type: &str,
    ) -> Result<i64> {
        if byte_len < 0 {
            anyhow::bail!("artifact byte length must be non-negative");
        }
        crate::safe_relative_path(relative_path)?;
        let mut client = self.connect()?;
        client.execute(
            "INSERT INTO artifacts(sha256,byte_len,relative_path,media_type,created_at) VALUES ($1,$2,$3,$4,CURRENT_TIMESTAMP) ON CONFLICT(sha256) DO NOTHING",
            &[&sha256, &byte_len, &relative_path, &media_type],
        )?;
        let existing = client.query_one(
            "SELECT id,byte_len,relative_path,media_type FROM artifacts WHERE sha256=$1",
            &[&sha256],
        )?;
        let existing_len: i64 = existing.get(1);
        let existing_path: String = existing.get(2);
        let existing_media: String = existing.get(3);
        if existing_len != byte_len
            || existing_path != relative_path
            || existing_media != media_type
        {
            anyhow::bail!("artifact identity conflicts with existing metadata");
        }
        Ok(existing.get(0))
    }

    pub fn artifact_root(&self) -> &Path {
        &self.artifact_root
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_fetch_status, validate_persisted_versions, MIGRATIONS};

    #[test]
    fn postgres_migrations_are_ordered_and_use_ported_types() {
        assert_eq!(
            MIGRATIONS.iter().map(|m| m.version).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert!(MIGRATIONS[0]
            .sql
            .contains("BIGINT GENERATED ALWAYS AS IDENTITY"));
        assert!(MIGRATIONS[0].sql.contains("enabled BOOLEAN"));
        assert!(MIGRATIONS[2].sql.contains("JSONB"));
        assert!(validate_persisted_versions(&[1, 2, 3], 4).is_ok());
        assert!(validate_persisted_versions(&[1, 3], 4).is_err());
        assert!(validate_persisted_versions(&[1, 2, 99], 4).is_err());
        assert!(validate_fetch_status("succeeded").is_ok());
        assert!(validate_fetch_status("failed").is_ok());
        assert!(validate_fetch_status("running").is_err());
    }
}
