mod integrity;
mod recovery;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use mg_brief::cve::{adapt_cve_json5, CveRecord, CveVersion, StableId};
use mg_brief::{asset::AssetImportDocument, CveArtifactInput, ItemQuery, Store};
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use serde_json::to_string_pretty;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_ASSET_IMPORT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "mg-brief",
    version,
    about = "Local-first RSS/Atom artifact collector"
)]
struct Cli {
    #[arg(long, env = "MG_BRIEF_DB")]
    db: Option<PathBuf>,
    #[arg(long, env = "MG_BRIEF_ARTIFACT_ROOT")]
    artifact_root: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Register {
        name: String,
        url: String,
        #[arg(long)]
        user_agent: Option<String>,
        /// Also show this source on the live ticker (mg-feedr)
        #[arg(long)]
        ticker: bool,
        /// Seconds between ticker checks (30–86400; default 300)
        #[arg(long, requires = "ticker")]
        every: Option<i64>,
    },
    /// Show or hide a source on the live ticker
    Ticker {
        name: String,
        #[arg(value_parser = ["on", "off"])]
        state: String,
        /// Seconds between ticker checks (30–86400)
        #[arg(long)]
        every: Option<i64>,
    },
    /// Stored headlines, oldest first; pass the last id back as --since to get only newer ones
    Items {
        #[arg(long)]
        since: Option<i64>,
        /// Only sources on the ticker
        #[arg(long)]
        ticker: bool,
        #[arg(long)]
        source: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Sources,
    Fetch {
        name: String,
        #[arg(long, default_value_t = 10 * 1024 * 1024)]
        max_bytes: u64,
        #[arg(long, default_value_t = 20)]
        timeout_seconds: u64,
    },
    Export {
        #[arg(long)]
        json: bool,
    },
    Status,
    /// Report embedded migration state without opening the store for writing
    Migrations,
    /// Check all catalog pages without migrating or changing data
    Integrity {
        #[arg(long, required = true)]
        acknowledge_offline: bool,
    },
    /// Recover through a private backup; stop mg-feedr and every writer to this mg-brief catalog first
    Recover {
        #[arg(long, required = true)]
        acknowledge_offline: bool,
        /// Install only if the recovered catalog validates and exactly preserves readable table records
        #[arg(long)]
        apply: bool,
        /// Permit strict row subsets only in sources, fetch_runs, artifacts, and provenance
        #[arg(long, requires = "apply")]
        allow_record_loss: bool,
        /// Require and restore every source from an authoritative feed-seed manifest
        #[arg(long, value_name = "JSON")]
        seed_manifest: Option<PathBuf>,
    },
    Cve {
        #[command(subcommand)]
        command: CveCommand,
    },
    Asset {
        #[command(subcommand)]
        command: AssetCommand,
    },
}

#[derive(Subcommand)]
enum AssetCommand {
    Import {
        #[arg(long)]
        input: PathBuf,
    },
    List {
        #[arg(long)]
        as_of: Option<DateTime<Utc>>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    Inspect {
        asset_id: String,
        #[arg(long)]
        as_of: Option<DateTime<Utc>>,
        #[arg(long, default_value_t = 100)]
        observation_limit: usize,
    },
}

#[derive(Subcommand)]
enum CveCommand {
    ImportCve5 {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        locator: String,
        #[arg(long)]
        retrieved_at: DateTime<Utc>,
    },
    Ingest {
        #[arg(long)]
        input: PathBuf,
    },
    Current {
        cve_id: String,
    },
    History {
        cve_id: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        cursor: Option<String>,
    },
}

#[derive(Deserialize)]
struct CveIngestDocument {
    record: CveRecord,
    version: CveVersion,
    artifacts: Vec<CveArtifactInput>,
}
fn status(db: &Path) -> serde_json::Value {
    if !db.is_file() {
        return serde_json::json!({
            "schema": "mg.brief.status/1",
            "status": "unconfigured",
            "counts": {"sources": 0, "cve_records": 0, "assets": 0}
        });
    }
    let connection = match Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(connection) => connection,
        Err(_) => {
            return serde_json::json!({
                "schema": "mg.brief.status/1",
                "status": "unavailable",
                "counts": {"sources": 0, "cve_records": 0, "assets": 0}
            })
        }
    };
    let count = |table: &str| -> Option<i64> {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .ok()
    };
    let Some(sources) = count("sources") else {
        return serde_json::json!({
            "schema": "mg.brief.status/1",
            "status": "unavailable",
            "counts": {"sources": 0, "cve_records": 0, "assets": 0}
        });
    };
    serde_json::json!({
        "schema": "mg.brief.status/1",
        "status": "ready",
        "counts": {
            "sources": sources,
            "cve_records": count("cve_versions").unwrap_or(0),
            "assets": count("asset_records").unwrap_or(0)
        }
    })
}

fn ensure_feedr_inactive() -> Result<()> {
    let output = std::process::Command::new("/usr/bin/timeout")
        .args([
            "--signal=TERM",
            "--kill-after=1s",
            "10s",
            "/usr/bin/systemctl",
            "--user",
            "show",
            "mg-feedr.service",
            "--property=ActiveState",
            "--value",
        ])
        .output()
        .context("checking mg-feedr.service before catalog inspection or recovery")?;
    if !output.status.success() {
        anyhow::bail!("cannot verify that mg-feedr.service is stopped");
    }
    let state = String::from_utf8_lossy(&output.stdout);
    require_feedr_inactive_state(state.trim())
}

fn require_feedr_inactive_state(state: &str) -> Result<()> {
    if state == "inactive" {
        Ok(())
    } else {
        anyhow::bail!("mg-feedr.service must be inactive before catalog inspection or recovery")
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let (_, root) = mg_brief::default_paths();
    let db = mg_brief::database_path(cli.db)?;
    if matches!(cli.command, Command::Status) {
        println!("{}", to_string_pretty(&status(&db))?);
        return Ok(());
    }
    // Read the ledger without migrating, so a drifted catalog can be inspected
    // rather than only refused.
    if matches!(cli.command, Command::Migrations) {
        let path = db;
        let states = if path.is_file() {
            let connection = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            mg_brief::migration_status(&connection)?
        } else {
            mg_brief::migration_status(&rusqlite::Connection::open_in_memory()?)?
        };
        println!("{}", to_string_pretty(&states)?);
        return Ok(());
    }
    if let Command::Integrity {
        acknowledge_offline,
    } = &cli.command
    {
        ensure_feedr_inactive()?;
        let snapshot = recovery::snapshot_for_integrity(&db, *acknowledge_offline)?;
        println!(
            "{}",
            to_string_pretty(&integrity::inspect(snapshot.database_path()))?
        );
        return Ok(());
    }
    if let Command::Recover {
        apply,
        allow_record_loss,
        acknowledge_offline,
        seed_manifest,
    } = &cli.command
    {
        ensure_feedr_inactive()?;
        let report = recovery::recover_with_seed_manifest(
            &db,
            *apply,
            *allow_record_loss,
            *acknowledge_offline,
            seed_manifest.as_deref(),
        )?;
        println!("{}", to_string_pretty(&report)?);
        return Ok(());
    }
    let store = Store::open(db, cli.artifact_root.unwrap_or(root))?;
    match cli.command {
        Command::Register {
            name,
            url,
            user_agent,
            ticker,
            every,
        } => {
            let mut source = store.register(&name, &url, user_agent.as_deref())?;
            if ticker {
                source = store.set_ticker(&name, true, every)?;
            }
            println!("{}", to_string_pretty(&source)?)
        }
        Command::Ticker { name, state, every } => println!(
            "{}",
            to_string_pretty(&store.set_ticker(&name, state == "on", every)?)?
        ),
        Command::Items {
            since,
            ticker,
            source,
            limit,
        } => println!(
            "{}",
            to_string_pretty(&store.items(&ItemQuery {
                since,
                ticker_only: ticker,
                source,
                unread_only: false,
                saved_only: false,
                limit,
            })?)?
        ),
        Command::Sources => println!("{}", to_string_pretty(&store.list_sources()?)?),
        Command::Fetch {
            name,
            max_bytes,
            timeout_seconds,
        } => println!(
            "{}",
            to_string_pretty(&store.fetch(&name, max_bytes, timeout_seconds)?)?
        ),
        Command::Export { json } => {
            if !json {
                anyhow::bail!("export requires --json")
            }
            println!("{}", to_string_pretty(&store.export_interop_snapshot()?)?)
        }
        Command::Status
        | Command::Migrations
        | Command::Integrity { .. }
        | Command::Recover { .. } => {
            unreachable!("all are handled before opening the store")
        }
        Command::Cve { command } => match command {
            CveCommand::ImportCve5 {
                input,
                locator,
                retrieved_at,
            } => {
                let bytes = std::fs::read(&input)?;
                if bytes.len() > 64 * 1024 * 1024 {
                    anyhow::bail!("CVE JSON 5 document is too large")
                }
                let adapted = adapt_cve_json5(&bytes, &locator, retrieved_at)?;
                let artifact = CveArtifactInput {
                    source_id: StableId::new("cve-program")?,
                    locator,
                    path: input,
                    media_type: "application/json".into(),
                };
                println!(
                    "{}",
                    to_string_pretty(&store.ingest_cve(
                        &adapted.record,
                        &adapted.version,
                        &[artifact]
                    )?)?
                );
            }
            CveCommand::Ingest { input } => {
                let bytes = std::fs::read(input)?;
                if bytes.len() > 64 * 1024 * 1024 {
                    anyhow::bail!("CVE ingest document is too large")
                }
                let document: CveIngestDocument = serde_json::from_slice(&bytes)?;
                println!(
                    "{}",
                    to_string_pretty(&store.ingest_cve(
                        &document.record,
                        &document.version,
                        &document.artifacts
                    )?)?
                );
            }
            CveCommand::Current { cve_id } => {
                println!("{}", to_string_pretty(&store.current_cve(&cve_id)?)?)
            }
            CveCommand::History {
                cve_id,
                limit,
                cursor,
            } => println!(
                "{}",
                to_string_pretty(&store.cve_history(&cve_id, limit, cursor.as_deref())?)?
            ),
        },
        Command::Asset { command } => match command {
            AssetCommand::Import { input } => {
                let bytes = read_bounded_input(&input, MAX_ASSET_IMPORT_BYTES)?;
                let document: AssetImportDocument = serde_json::from_slice(&bytes)?;
                println!("{}", to_string_pretty(&store.import_assets(&document)?)?);
            }
            AssetCommand::List { as_of, limit } => println!(
                "{}",
                to_string_pretty(&store.list_assets(as_of.unwrap_or_else(Utc::now), limit)?)?
            ),
            AssetCommand::Inspect {
                asset_id,
                as_of,
                observation_limit,
            } => println!(
                "{}",
                to_string_pretty(&store.inspect_asset(
                    &asset_id,
                    as_of.unwrap_or_else(Utc::now),
                    observation_limit
                )?)?
            ),
        },
    }
    Ok(())
}

fn read_bounded_input(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        anyhow::bail!("asset import document is unavailable or too large")
    }
    let mut file = File::open(path)?;
    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref().take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("asset import document is unavailable or too large")
    }
    Ok(bytes)
}

#[cfg(test)]
mod feedr_state_tests {
    use super::{require_feedr_inactive_state, Cli};
    use clap::Parser;

    #[test]
    fn only_inactive_feedr_unit_state_is_accepted() {
        assert!(require_feedr_inactive_state("inactive").is_ok());
        assert!(require_feedr_inactive_state("activating").is_err());
        assert!(require_feedr_inactive_state("active").is_err());
        assert!(require_feedr_inactive_state("failed").is_err());
    }

    #[test]
    fn integrity_cli_requires_offline_acknowledgement() {
        assert!(Cli::try_parse_from(["mg-brief", "integrity"]).is_err());
        assert!(Cli::try_parse_from(["mg-brief", "integrity", "--acknowledge-offline"]).is_ok());
    }

    #[test]
    fn recovery_cli_requires_offline_acknowledgement() {
        assert!(Cli::try_parse_from(["mg-brief", "recover"]).is_err());
        assert!(Cli::try_parse_from(["mg-brief", "recover", "--acknowledge-offline"]).is_ok());
    }

    #[test]
    fn recovery_cli_accepts_a_historical_seed_manifest_path() {
        assert!(Cli::try_parse_from([
            "mg-brief",
            "recover",
            "--acknowledge-offline",
            "--seed-manifest",
            "/private/seed-manifest.json"
        ])
        .is_ok());
    }

    #[test]
    fn recovery_loss_override_requires_apply_and_offline_acknowledgement() {
        assert!(Cli::try_parse_from([
            "mg-brief",
            "recover",
            "--acknowledge-offline",
            "--allow-record-loss"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "mg-brief",
            "recover",
            "--acknowledge-offline",
            "--apply",
            "--allow-record-loss"
        ])
        .is_ok());
    }
}
