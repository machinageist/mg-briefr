use anyhow::Result;
use clap::{Parser, Subcommand};
use mg_brief::Store;
use serde_json::to_string_pretty;
use std::{env, path::PathBuf};

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
fn main() -> Result<()> {
    let cli = Cli::parse();
    let (db, root) = defaults();
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
    }
    Ok(())
}
