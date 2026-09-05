use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use mg_brief::cve::{adapt_cve_json5, CveRecord, CveVersion, StableId};
use mg_brief::{asset::AssetImportDocument, CveArtifactInput, Store};
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use serde_json::to_string_pretty;
use std::{
    env,
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
fn defaults() -> (PathBuf, PathBuf) {
    let data = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    let config = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    (
        env::var_os("MG_BRIEF_DB")
            .map(PathBuf::from)
            .unwrap_or_else(|| data.join("mg-brief/catalog.sqlite")),
        env::var_os("MG_BRIEF_ARTIFACT_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| config.join("mg-brief/artifacts")),
    )
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let (db, root) = defaults();
    if matches!(cli.command, Command::Status) {
        println!("{}", to_string_pretty(&status(&cli.db.unwrap_or(db)))?);
        return Ok(());
    }
    // Read the ledger without migrating, so a drifted catalog can be inspected
    // rather than only refused.
    if matches!(cli.command, Command::Migrations) {
        let path = cli.db.unwrap_or(db);
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
    let store = Store::open(cli.db.unwrap_or(db), cli.artifact_root.unwrap_or(root))?;
    match cli.command {
        Command::Register {
            name,
            url,
            user_agent,
        } => println!(
            "{}",
            to_string_pretty(&store.register(&name, &url, user_agent.as_deref())?)?
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
        Command::Status | Command::Migrations => {
            unreachable!("both are handled before opening the store")
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
