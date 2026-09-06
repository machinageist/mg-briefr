use crate::cve::{Asset, AssetObservation, AssetObservationCoverage, StableId};
use crate::{Store, JSON_VERSION};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

const ASSET_IMPORT_SCHEMA: &str = "mg-brief.asset-import/v1";
const MAX_IMPORT_ENTRIES: usize = 10_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetImportDocument {
    pub schema: String,
    pub entries: Vec<AssetImportEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetImportEntry {
    pub asset: Asset,
    pub observation: AssetObservation,
}

#[derive(Debug, Serialize)]
pub struct AssetImportResult {
    pub schema: &'static str,
    pub inserted_assets: usize,
    pub inserted_observations: usize,
    pub replayed_entries: usize,
}

#[derive(Debug, Serialize)]
pub struct AssetListPage {
    pub schema: &'static str,
    pub items: Vec<AssetListItem>,
}

#[derive(Debug, Serialize)]
pub struct AssetListItem {
    pub asset: Asset,
    pub inventory_status: InventoryStatus,
    pub effective_observation: Option<AssetObservation>,
    pub observation_count: usize,
}

#[derive(Debug, Serialize)]
pub struct AssetInspection {
    pub schema: &'static str,
    pub asset: Asset,
    pub inventory_status: InventoryStatus,
    pub effective_observation: Option<AssetObservation>,
    pub observations: Vec<AssetObservation>,
    pub observation_count: usize,
    pub observations_truncated: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryStatus {
    Fresh,
    Incomplete,
    Unknown,
    Stale,
}

impl Store {
    /// Import immutable assets and observations in one transaction.
    pub fn import_assets(&self, document: &AssetImportDocument) -> Result<AssetImportResult> {
        if document.schema != ASSET_IMPORT_SCHEMA {
            bail!("unsupported asset import schema")
        }
        if document.entries.len() > MAX_IMPORT_ENTRIES {
            bail!("asset import has too many entries")
        }

        let mut connection = self.conn()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut inserted_assets = 0;
        let mut inserted_observations = 0;
        let mut replayed_entries = 0;

        for entry in &document.entries {
            entry.asset.validate().context("invalid asset")?;
            entry
                .observation
                .validate()
                .context("invalid asset observation")?;
            if entry.asset.id != entry.observation.asset_id {
                bail!("asset and observation identity differ")
            }

            let asset_json = serde_json::to_string(&entry.asset.storage_value()?)?;
            let existing_asset = tx
                .query_one("SELECT asset_json FROM asset_records WHERE id=$1",
                    &[&entry.asset.id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let asset_inserted = match existing_asset {
                Some(existing) if existing == asset_json => false,
                Some(_) => bail!("immutable asset conflict"),
                None => {
                    tx.execute(
                        "INSERT INTO asset_records(id,created_at,asset_json) VALUES ($1,$2,$3)",
                        &[&entry.asset.id.as_str(), &entry.asset.created_at.to_rfc3339(), &asset_json],
                    )?;
                    inserted_assets += 1;
                    true
                }
            };

            if let Some(corrected_id) = &entry.observation.corrects_observation_id {
                let corrected = tx
                    .query_one("SELECT id,asset_id,observed_at,corrects_observation_id,observation_json FROM asset_observations WHERE id=$1",
                        &[&corrected_id.as_str()],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<String>>(3)?, row.get::<_, String>(4)?)),
                    )
                    .optional()?
                    .context("corrected observation not found")?;
                let corrected = decode_observation(
                    &corrected.0,
                    &corrected.1,
                    &corrected.2,
                    corrected.3.as_deref(),
                    &corrected.4,
                )?;
                if corrected.asset_id != entry.asset.id {
                    bail!("corrected observation belongs to a different asset")
                }
                if entry.observation.observed_at <= corrected.observed_at {
                    bail!("corrected observation must be newer than its target")
                }
            }

            let observation_json = serde_json::to_string(&entry.observation.storage_value()?)?;
            let existing_observation = tx
                .query_row(
                    "SELECT observation_json FROM asset_observations WHERE id=$1", &[&entry.observation.id.as_str()]).map(|row| row.get::<_, String>(0))
                .optional()?;
            let observation_inserted = match existing_observation {
                Some(existing) if existing == observation_json => false,
                Some(_) => bail!("immutable asset observation conflict"),
                None => {
                    tx.execute(
                        "INSERT INTO asset_observations(id,asset_id,observed_at,corrects_observation_id,observation_json) VALUES ($1,$2,$3,$4,$5)",
                        &[&entry.observation.id.as_str(), &entry.observation.asset_id.as_str(), &entry.observation.observed_at.to_rfc3339(), &entry
                                .observation
                                .corrects_observation_id
                                .as_ref()
                                .map(StableId::as_str), &observation_json],
                    )?;
                    inserted_observations += 1;
                    true
                }
            };

            if !asset_inserted && !observation_inserted {
                replayed_entries += 1;
            }
        }

        tx.commit()?;
        Ok(AssetImportResult {
            schema: JSON_VERSION,
            inserted_assets,
            inserted_observations,
            replayed_entries,
        })
    }

    pub fn list_assets(&self, as_of: DateTime<Utc>, limit: usize) -> Result<AssetListPage> {
        validate_asset_limit(limit, "asset list")?;
        let connection = self.conn()?;
        let mut statement =
            connection.prepare("SELECT id,asset_json FROM asset_records ORDER BY id LIMIT $1")?;
        let assets = statement
            .query_map(&[&limit as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let items = assets
            .into_iter()
            .map(|(asset_id, asset_json)| {
                let asset = decode_asset(&asset_id, &asset_json)?;
                let effective_observation =
                    load_effective_observation(&connection, asset.id.as_str(), as_of)?;
                Ok(AssetListItem {
                    asset,
                    inventory_status: inventory_status(effective_observation.as_ref(), as_of),
                    effective_observation,
                    observation_count: observation_count(&connection, &asset_id)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(AssetListPage {
            schema: JSON_VERSION,
            items,
        })
    }

    pub fn inspect_asset(
        &self,
        asset_id: &str,
        as_of: DateTime<Utc>,
        observation_limit: usize,
    ) -> Result<AssetInspection> {
        validate_asset_limit(observation_limit, "asset observation")?;
        let asset_id = StableId::new(asset_id)?;
        let connection = self.conn()?;
        let (stored_id, asset_json) = connection
            .query_row(
                "SELECT id,asset_json FROM asset_records WHERE id=$1",
                &[&asset_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .context("asset not found")?;
        let asset = decode_asset(&stored_id, &asset_json)?;
        let effective_observation =
            load_effective_observation(&connection, asset.id.as_str(), as_of)?;
        let observation_count = observation_count(&connection, asset.id.as_str())?;
        let observations =
            load_recent_observations(&connection, asset.id.as_str(), observation_limit)?;
        Ok(AssetInspection {
            schema: JSON_VERSION,
            asset,
            inventory_status: inventory_status(effective_observation.as_ref(), as_of),
            effective_observation,
            observations,
            observation_count,
            observations_truncated: observation_count > observation_limit,
        })
    }
}

fn load_recent_observations(
    connection: &rusqlite::Connection,
    asset_id: &str,
    limit: usize,
) -> Result<Vec<AssetObservation>> {
    let mut statement = connection.prepare(
        "SELECT id,asset_id,observed_at,corrects_observation_id,observation_json FROM asset_observations WHERE asset_id=$1 ORDER BY observed_at DESC,id DESC LIMIT $2",
    )?;
    let observations = statement
        .query_map(&[&asset_id, &limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .map(|row| {
            let (id, stored_asset_id, observed_at, corrects, json) = row?;
            decode_observation(
                &id,
                &stored_asset_id,
                &observed_at,
                corrects.as_deref(),
                &json,
            )
        })
        .collect();
    observations
}

fn load_effective_observation(
    connection: &rusqlite::Connection,
    asset_id: &str,
    as_of: DateTime<Utc>,
) -> Result<Option<AssetObservation>> {
    let stored = connection
        .query_row(
            "SELECT id,asset_id,observed_at,corrects_observation_id,observation_json FROM asset_observations WHERE asset_id=$1 AND observed_at<=$2 ORDER BY CASE WHEN corrects_observation_id IS NOT NULL THEN 1 ELSE 0 END DESC,observed_at DESC,id DESC LIMIT 1",
            &[&asset_id, &as_of.to_rfc3339()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(|(id, stored_asset_id, observed_at, corrects, json)| {
            decode_observation(
                &id,
                &stored_asset_id,
                &observed_at,
                corrects.as_deref(),
                &json,
            )
        })
        .transpose()
}

fn observation_count(connection: &rusqlite::Connection, asset_id: &str) -> Result<usize> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM asset_observations WHERE asset_id=$1", &[&asset_id]).map(|row| row.get(0))?;
    usize::try_from(count).context("invalid stored asset observation count")
}

fn decode_asset(stored_id: &str, json: &str) -> Result<Asset> {
    let asset: Asset = serde_json::from_str(json).context("invalid stored asset")?;
    if asset.id.as_str() != stored_id {
        bail!("stored asset identity conflict")
    }
    Ok(asset)
}

fn decode_observation(
    stored_id: &str,
    stored_asset_id: &str,
    stored_observed_at: &str,
    stored_corrects: Option<&str>,
    json: &str,
) -> Result<AssetObservation> {
    let observation: AssetObservation =
        serde_json::from_str(json).context("invalid stored asset observation")?;
    if observation.id.as_str() != stored_id
        || observation.asset_id.as_str() != stored_asset_id
        || observation.observed_at.to_rfc3339() != stored_observed_at
        || observation
            .corrects_observation_id
            .as_ref()
            .map(StableId::as_str)
            != stored_corrects
    {
        bail!("stored asset observation metadata conflict")
    }
    Ok(observation)
}

fn inventory_status(
    observation: Option<&AssetObservation>,
    as_of: DateTime<Utc>,
) -> InventoryStatus {
    let Some(observation) = observation else {
        return InventoryStatus::Unknown;
    };
    if observation
        .stale_after
        .is_some_and(|stale_after| as_of >= stale_after)
    {
        return InventoryStatus::Stale;
    }
    match observation.coverage {
        AssetObservationCoverage::Complete => InventoryStatus::Fresh,
        AssetObservationCoverage::Incomplete => InventoryStatus::Incomplete,
        AssetObservationCoverage::Unknown => InventoryStatus::Unknown,
    }
}

fn validate_asset_limit(limit: usize, operation: &str) -> Result<()> {
    if !(1..=100).contains(&limit) {
        bail!("{operation} limit must be between 1 and 100")
    }
    Ok(())
}
