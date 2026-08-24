//! Validated, provenance-preserving CVE and inventory domain contracts.
//!
//! This module is intentionally persistence- and transport-agnostic. Callers must
//! validate records before storing or sending them to an adapter.

use chrono::{DateTime, Utc};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt;

const MAX_IDENTIFIER_LEN: usize = 256;
const MAX_TEXT_LEN: usize = 32 * 1024;
const MAX_LIST_ITEMS: usize = 256;
const MAX_MAP_ITEMS: usize = 256;
const REDACTED_LOCAL_LOCATOR: &str = "[redacted-local-locator]";
const REDACTED_HTTP_LOCATOR: &str = "[redacted-http-locator]";
const REDACTED_LOCATOR: &str = "[redacted-locator]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    Empty(&'static str),
    TooLong(&'static str),
    InvalidIdentifier(&'static str),
    InvalidTimestamp(&'static str),
    InvalidRange(&'static str),
    MissingProvenance(&'static str),
    InvalidState(&'static str),
    UnsafeLocator(&'static str),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(field) => write!(f, "{field} must not be empty"),
            Self::TooLong(field) => write!(f, "{field} is too long"),
            Self::InvalidIdentifier(field) => write!(f, "{field} has an invalid identifier"),
            Self::InvalidTimestamp(field) => write!(f, "{field} has an invalid timestamp"),
            Self::InvalidRange(field) => write!(f, "{field} has an invalid range"),
            Self::MissingProvenance(field) => write!(f, "{field} requires provenance"),
            Self::InvalidState(field) => write!(f, "{field} has an invalid state"),
            Self::UnsafeLocator(field) => write!(f, "{field} is unsafe to publish"),
        }
    }
}
impl std::error::Error for ValidationError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct StableId(String);
impl StableId {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_token(&value, "id")?;
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for StableId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawSourceReference")]
pub struct SourceReference {
    pub source_id: StableId,
    pub locator: String,
    pub content_sha256: Option<String>,
    pub retrieved_at: DateTime<Utc>,
    pub source_version: Option<String>,
}
#[derive(Debug, Deserialize)]
struct RawSourceReference {
    source_id: StableId,
    locator: String,
    content_sha256: Option<String>,
    retrieved_at: DateTime<Utc>,
    source_version: Option<String>,
}

impl TryFrom<RawSourceReference> for SourceReference {
    type Error = ValidationError;
    fn try_from(raw: RawSourceReference) -> Result<Self, Self::Error> {
        let value = Self {
            source_id: raw.source_id,
            locator: raw.locator,
            content_sha256: raw.content_sha256,
            retrieved_at: raw.retrieved_at,
            source_version: raw.source_version,
        };
        value.validate()?;
        Ok(value)
    }
}

impl SourceReference {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_token(self.source_id.as_str(), "source_id")?;
        validate_text(&self.locator, "locator")?;
        validate_timestamp(self.retrieved_at, "retrieved_at")?;
        if let Some(hash) = &self.content_sha256 {
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ValidationError::InvalidIdentifier("content_sha256"));
            }
        }
        if let Some(version) = &self.source_version {
            validate_token(version, "source_version")?;
        }
        Ok(())
    }
}

impl Serialize for SourceReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Public<'a> {
            source_id: &'a StableId,
            locator: String,
            content_sha256: &'a Option<String>,
            retrieved_at: DateTime<Utc>,
            source_version: &'a Option<String>,
        }
        Public {
            source_id: &self.source_id,
            locator: public_locator(&self.locator),
            content_sha256: &self.content_sha256,
            retrieved_at: self.retrieved_at,
            source_version: &self.source_version,
        }
        .serialize(serializer)
    }
}

fn public_locator(locator: &str) -> String {
    if matches!(
        locator,
        REDACTED_LOCAL_LOCATOR | REDACTED_HTTP_LOCATOR | REDACTED_LOCATOR
    ) {
        return locator.to_owned();
    }
    if let Ok(url) = url::Url::parse(locator) {
        return match url.scheme() {
            "file" => REDACTED_LOCAL_LOCATOR.into(),
            "http" | "https" => REDACTED_HTTP_LOCATOR.into(),
            _ => REDACTED_LOCATOR.into(),
        };
    }
    if locator.starts_with('/')
        || locator.starts_with('~')
        || locator.contains('\\')
        || locator.starts_with("./")
        || locator.starts_with("../")
        || locator.contains('/')
    {
        return REDACTED_LOCAL_LOCATOR.into();
    }
    REDACTED_LOCATOR.into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Exact,
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawProvenance")]
pub struct Provenance {
    pub references: Vec<SourceReference>,
    pub confidence: Confidence,
    pub observed_at: DateTime<Utc>,
}
#[derive(Debug, Deserialize)]
struct RawProvenance {
    references: Vec<SourceReference>,
    confidence: Confidence,
    observed_at: DateTime<Utc>,
}

impl TryFrom<RawProvenance> for Provenance {
    type Error = ValidationError;
    fn try_from(raw: RawProvenance) -> Result<Self, Self::Error> {
        let value = Self {
            references: raw.references,
            confidence: raw.confidence,
            observed_at: raw.observed_at,
        };
        value.validate()?;
        Ok(value)
    }
}

impl Provenance {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.references.is_empty() || self.references.len() > MAX_LIST_ITEMS {
            return Err(ValidationError::MissingProvenance("provenance"));
        }
        validate_timestamp(self.observed_at, "observed_at")?;
        for reference in &self.references {
            reference.validate()?;
            if reference.retrieved_at > self.observed_at {
                return Err(ValidationError::InvalidTimestamp("provenance"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCveRecord")]
pub struct CveRecord {
    pub id: StableId,
    pub aliases: Vec<String>,
    pub descriptions: BTreeMap<String, String>,
    pub cna: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub modified_at: DateTime<Utc>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub provenance: Provenance,
}
#[derive(Debug, Deserialize)]
struct RawCveRecord {
    id: StableId,
    aliases: Vec<String>,
    descriptions: BTreeMap<String, String>,
    cna: Option<String>,
    published_at: Option<DateTime<Utc>>,
    modified_at: DateTime<Utc>,
    withdrawn_at: Option<DateTime<Utc>>,
    provenance: Provenance,
}

impl TryFrom<RawCveRecord> for CveRecord {
    type Error = ValidationError;
    fn try_from(raw: RawCveRecord) -> Result<Self, Self::Error> {
        let value = Self {
            id: raw.id,
            aliases: raw.aliases,
            descriptions: raw.descriptions,
            cna: raw.cna,
            published_at: raw.published_at,
            modified_at: raw.modified_at,
            withdrawn_at: raw.withdrawn_at,
            provenance: raw.provenance,
        };
        value.validate()?;
        Ok(value)
    }
}

impl CveRecord {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_cve_id(self.id.as_str(), "id")?;
        if self.aliases.len() > MAX_LIST_ITEMS || self.descriptions.len() > MAX_MAP_ITEMS {
            return Err(ValidationError::TooLong("cve_record"));
        }
        for alias in &self.aliases {
            validate_token(alias, "alias")?;
        }
        for (language, text) in &self.descriptions {
            validate_token(language, "description_language")?;
            validate_text(text, "description")?;
        }
        if let Some(cna) = &self.cna {
            validate_token(cna, "cna")?;
        }
        validate_timestamp(self.modified_at, "modified_at")?;
        if let Some(published) = self.published_at {
            validate_timestamp(published, "published_at")?;
            if published > self.modified_at {
                return Err(ValidationError::InvalidTimestamp("published_at"));
            }
        }
        if let Some(withdrawn) = self.withdrawn_at {
            validate_timestamp(withdrawn, "withdrawn_at")?;
            if withdrawn > self.modified_at {
                return Err(ValidationError::InvalidTimestamp("withdrawn_at"));
            }
            if let Some(published) = self.published_at {
                if withdrawn < published {
                    return Err(ValidationError::InvalidState("withdrawn_at"));
                }
            }
        }
        self.provenance.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCveVersion")]
pub struct CveVersion {
    pub id: StableId,
    pub cve_id: StableId,
    pub revision: String,
    pub modified_at: DateTime<Utc>,
    pub fields: BTreeMap<String, serde_json::Value>,
    pub provenance: Provenance,
}
impl CveVersion {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_token(self.id.as_str(), "id")?;
        validate_cve_id(self.cve_id.as_str(), "cve_id")?;
        validate_token(&self.revision, "revision")?;
        validate_timestamp(self.modified_at, "modified_at")?;
        if self.fields.len() > MAX_MAP_ITEMS {
            return Err(ValidationError::TooLong("fields"));
        }
        for (key, value) in &self.fields {
            validate_token(key, "field")?;
            if value.to_string().len() > MAX_TEXT_LEN {
                return Err(ValidationError::TooLong("field"));
            }
        }
        self.provenance.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawVersionRange")]
pub struct VersionRange {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub raw: String,
}
impl VersionRange {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_text(&self.raw, "raw")?;
        if self.introduced.is_none() && self.fixed.is_none() {
            return Err(ValidationError::InvalidRange("range"));
        }
        for value in [&self.introduced, &self.fixed].into_iter().flatten() {
            validate_version(value, "version")?;
            if !self.raw.split_whitespace().any(|part| part == value) {
                return Err(ValidationError::InvalidRange("raw"));
            }
        }
        if let (Some(introduced), Some(fixed)) = (&self.introduced, &self.fixed) {
            if introduced == fixed
                || compare_versions(introduced, fixed) != Some(std::cmp::Ordering::Less)
            {
                return Err(ValidationError::InvalidRange("range"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawAdvisoryRecord")]
pub struct AdvisoryRecord {
    pub id: StableId,
    pub source: SourceReference,
    pub vendor: String,
    pub product: String,
    pub affected_ranges: Vec<VersionRange>,
    pub fixed_versions: Vec<String>,
    pub mitigations: Vec<String>,
    pub references: Vec<String>,
    pub source_version: Option<String>,
}

impl Serialize for AdvisoryRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Public<'a> {
            id: &'a StableId,
            source: &'a SourceReference,
            vendor: &'a str,
            product: &'a str,
            affected_ranges: &'a Vec<VersionRange>,
            fixed_versions: &'a Vec<String>,
            mitigations: &'a Vec<String>,
            references: Vec<String>,
            source_version: &'a Option<String>,
        }
        Public {
            id: &self.id,
            source: &self.source,
            vendor: &self.vendor,
            product: &self.product,
            affected_ranges: &self.affected_ranges,
            fixed_versions: &self.fixed_versions,
            mitigations: &self.mitigations,
            references: self
                .references
                .iter()
                .map(|value| public_locator(value))
                .collect(),
            source_version: &self.source_version,
        }
        .serialize(serializer)
    }
}

impl AdvisoryRecord {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_token(self.id.as_str(), "id")?;
        validate_token(&self.vendor, "vendor")?;
        validate_token(&self.product, "product")?;
        self.source.validate()?;
        if self.affected_ranges.len() > MAX_LIST_ITEMS
            || self.fixed_versions.len() > MAX_LIST_ITEMS
            || self.mitigations.len() > MAX_LIST_ITEMS
            || self.references.len() > MAX_LIST_ITEMS
        {
            return Err(ValidationError::TooLong("advisory"));
        }
        if self.affected_ranges.is_empty() {
            return Err(ValidationError::InvalidRange("affected_ranges"));
        }
        for r in &self.affected_ranges {
            r.validate()?;
        }
        for v in &self.fixed_versions {
            validate_version(v, "fixed_version")?;
        }
        for value in &self.mitigations {
            validate_text(value, "mitigation")?;
        }
        for value in &self.references {
            validate_text(value, "reference")?;
        }
        if let Some(value) = &self.source_version {
            validate_token(value, "source_version")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Software,
    Hardware,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawAsset")]
pub struct Asset {
    pub id: StableId,
    pub kind: AssetKind,
    pub vendor: Option<String>,
    pub product: String,
    pub model: Option<String>,
    pub installed_version: Option<String>,
    pub package: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub provenance: Provenance,
    pub stale_after: Option<DateTime<Utc>>,
    pub user_corrected: bool,
}
impl Asset {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_token(self.id.as_str(), "id")?;
        validate_token(&self.product, "product")?;
        for (field, value) in [
            ("vendor", self.vendor.as_ref()),
            ("model", self.model.as_ref()),
            ("installed_version", self.installed_version.as_ref()),
            ("package", self.package.as_ref()),
            ("purl", self.purl.as_ref()),
            ("cpe", self.cpe.as_ref()),
        ] {
            if let Some(value) = value {
                validate_text(value, field)?;
            }
        }
        if self.kind == AssetKind::Software
            && self.installed_version.is_none()
            && self.package.is_none()
            && self.purl.is_none()
            && self.cpe.is_none()
        {
            return Err(ValidationError::InvalidState("software asset identity"));
        }
        self.provenance.validate()?;
        if let Some(t) = self.stale_after {
            validate_timestamp(t, "stale_after")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawAssetObservation")]
pub struct AssetObservation {
    pub id: StableId,
    pub asset_id: StableId,
    pub collector: String,
    pub raw_identifier: String,
    pub normalized_candidates: Vec<String>,
    pub observed_at: DateTime<Utc>,
    pub evidence: Vec<String>,
    pub provenance: Provenance,
}
impl AssetObservation {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_token(self.id.as_str(), "id")?;
        validate_token(self.asset_id.as_str(), "asset_id")?;
        validate_token(&self.collector, "collector")?;
        if self.normalized_candidates.len() > MAX_LIST_ITEMS || self.evidence.len() > MAX_LIST_ITEMS
        {
            return Err(ValidationError::TooLong("observation"));
        }
        for value in &self.normalized_candidates {
            validate_token(value, "candidate")?;
        }
        for value in &self.evidence {
            validate_text(value, "evidence")?;
        }
        validate_token(&self.raw_identifier, "raw_identifier")?;
        validate_timestamp(self.observed_at, "observed_at")?;
        self.provenance.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchStatus {
    ExactMatch,
    ProbableMatch,
    VulnerableVersion,
    FixedNotAffected,
    Unmatched,
    Unknown,
    ConflictingEvidence,
    StaleInventory,
    Withdrawn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawMatchEvidence")]
pub struct MatchEvidence {
    pub kind: String,
    pub value: String,
    pub source: Option<SourceReference>,
    pub explanation: String,
}
impl MatchEvidence {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_token(&self.kind, "kind")?;
        validate_text(&self.value, "value")?;
        validate_text(&self.explanation, "explanation")?;
        if let Some(s) = &self.source {
            s.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCveAssetMatch")]
pub struct CveAssetMatch {
    pub id: StableId,
    pub cve_id: StableId,
    pub asset_id: StableId,
    pub status: MatchStatus,
    pub confidence: Confidence,
    pub explanation: String,
    pub evidence: Vec<MatchEvidence>,
    pub matcher_version: String,
    pub observed_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub provenance: Provenance,
}
impl CveAssetMatch {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_token(self.id.as_str(), "id")?;
        validate_cve_id(self.cve_id.as_str(), "cve_id")?;
        validate_token(self.asset_id.as_str(), "asset_id")?;
        validate_token(&self.matcher_version, "matcher_version")?;
        validate_text(&self.explanation, "explanation")?;
        validate_timestamp(self.observed_at, "observed_at")?;
        if let Some(t) = self.resolved_at {
            validate_timestamp(t, "resolved_at")?;
            if t < self.observed_at {
                return Err(ValidationError::InvalidTimestamp("resolved_at"));
            }
        }
        if self.evidence.len() > MAX_LIST_ITEMS {
            return Err(ValidationError::TooLong("evidence"));
        }
        for e in &self.evidence {
            e.validate()?;
        }
        self.provenance.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionCause {
    NewCve,
    CveModified,
    CveWithdrawn,
    AdvisoryUpdated,
    InventoryChanged,
    UserCorrection,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCveStateTransition")]
pub struct CveStateTransition {
    pub id: StableId,
    pub match_id: StableId,
    pub from: Option<MatchStatus>,
    pub to: MatchStatus,
    pub cause: TransitionCause,
    pub changed_at: DateTime<Utc>,
    pub explanation: String,
    pub provenance: Provenance,
}
impl CveStateTransition {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_token(self.id.as_str(), "id")?;
        validate_token(self.match_id.as_str(), "match_id")?;
        validate_timestamp(self.changed_at, "changed_at")?;
        validate_text(&self.explanation, "explanation")?;
        if self.from == Some(self.to) {
            return Err(ValidationError::InvalidState("transition"));
        }
        if self.from == Some(MatchStatus::Withdrawn) && self.to != MatchStatus::Withdrawn {
            return Err(ValidationError::InvalidState("withdrawn transition"));
        }
        match &self.cause {
            TransitionCause::NewCve if self.from.is_some() => {
                return Err(ValidationError::InvalidState("new_cve transition"))
            }
            TransitionCause::CveWithdrawn if self.to != MatchStatus::Withdrawn => {
                return Err(ValidationError::InvalidState("withdrawn transition"))
            }
            TransitionCause::CveWithdrawn if self.from == Some(MatchStatus::Withdrawn) => {
                return Err(ValidationError::InvalidState("withdrawn transition"))
            }
            cause
                if self.to == MatchStatus::Withdrawn && *cause != TransitionCause::CveWithdrawn =>
            {
                return Err(ValidationError::InvalidState("withdrawn cause"))
            }
            _ => {}
        }
        validate_token(self.match_id.as_str(), "match_id")?;
        validate_token(self.id.as_str(), "id")?;
        self.provenance.validate()
    }
}

macro_rules! validated_wire {
    ($raw:ident, $ty:ident, { $($field:ident : $field_ty:ty),+ $(,)? }) => {
        #[derive(Debug, Deserialize)]
        struct $raw { $( $field: $field_ty, )+ }
        impl TryFrom<$raw> for $ty {
            type Error = ValidationError;
            fn try_from(raw: $raw) -> Result<Self, Self::Error> {
                let value = Self { $( $field: raw.$field, )+ };
                value.validate()?;
                Ok(value)
            }
        }
    };
}

validated_wire!(RawCveVersion, CveVersion, {
    id: StableId, cve_id: StableId, revision: String, modified_at: DateTime<Utc>,
    fields: BTreeMap<String, serde_json::Value>, provenance: Provenance
});
validated_wire!(RawVersionRange, VersionRange, {
    introduced: Option<String>, fixed: Option<String>, raw: String
});
validated_wire!(RawAdvisoryRecord, AdvisoryRecord, {
    id: StableId, source: SourceReference, vendor: String, product: String,
    affected_ranges: Vec<VersionRange>, fixed_versions: Vec<String>, mitigations: Vec<String>,
    references: Vec<String>, source_version: Option<String>
});
validated_wire!(RawAsset, Asset, {
    id: StableId, kind: AssetKind, vendor: Option<String>, product: String, model: Option<String>,
    installed_version: Option<String>, package: Option<String>, purl: Option<String>, cpe: Option<String>,
    provenance: Provenance, stale_after: Option<DateTime<Utc>>, user_corrected: bool
});
validated_wire!(RawAssetObservation, AssetObservation, {
    id: StableId, asset_id: StableId, collector: String, raw_identifier: String,
    normalized_candidates: Vec<String>, observed_at: DateTime<Utc>, evidence: Vec<String>, provenance: Provenance
});
validated_wire!(RawMatchEvidence, MatchEvidence, {
    kind: String, value: String, source: Option<SourceReference>, explanation: String
});
validated_wire!(RawCveAssetMatch, CveAssetMatch, {
    id: StableId, cve_id: StableId, asset_id: StableId, status: MatchStatus, confidence: Confidence,
    explanation: String, evidence: Vec<MatchEvidence>, matcher_version: String, observed_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>, provenance: Provenance
});
validated_wire!(RawCveStateTransition, CveStateTransition, {
    id: StableId, match_id: StableId, from: Option<MatchStatus>, to: MatchStatus, cause: TransitionCause,
    changed_at: DateTime<Utc>, explanation: String, provenance: Provenance
});

fn validate_version(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_LEN
        || value
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(ValidationError::InvalidRange(field));
    }
    Ok(())
}

fn compare_versions(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    let parse = |value: &str| {
        value
            .split('.')
            .map(|part| part.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()
    };
    let (mut left, mut right) = (parse(left)?, parse(right)?);
    while left.last() == Some(&0) {
        left.pop();
    }
    while right.last() == Some(&0) {
        right.pop();
    }
    let len = left.len().max(right.len());
    left.resize(len, 0);
    right.resize(len, 0);
    Some(left.cmp(&right))
}

fn validate_token(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty(field));
    }
    if value.len() > MAX_IDENTIFIER_LEN
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(ValidationError::InvalidIdentifier(field));
    }
    Ok(())
}
fn validate_text(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::Empty(field));
    }
    if value.len() > MAX_TEXT_LEN || value.chars().any(|c| c.is_control()) {
        return Err(ValidationError::TooLong(field));
    }
    Ok(())
}
fn validate_timestamp(value: DateTime<Utc>, field: &'static str) -> Result<(), ValidationError> {
    if value.timestamp() < 0 || value.timestamp() > 4_102_444_800 {
        return Err(ValidationError::InvalidTimestamp(field));
    }
    Ok(())
}
fn validate_cve_id(value: &str, field: &'static str) -> Result<(), ValidationError> {
    let bytes = value.as_bytes();
    let valid = bytes.len() >= 13
        && bytes.len() <= MAX_IDENTIFIER_LEN
        && bytes.get(0..4) == Some(b"CVE-")
        && bytes
            .get(4..8)
            .is_some_and(|part| part.iter().all(u8::is_ascii_digit))
        && bytes.get(8) == Some(&b'-')
        && bytes
            .get(9..)
            .is_some_and(|part| part.len() >= 4 && part.iter().all(u8::is_ascii_digit));
    if valid {
        Ok(())
    } else {
        Err(ValidationError::InvalidIdentifier(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dt() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }
    fn provenance() -> Provenance {
        Provenance {
            references: vec![SourceReference {
                source_id: StableId::new("nvd").unwrap(),
                locator: "https://example.test/cve.json".into(),
                content_sha256: Some("a".repeat(64)),
                retrieved_at: dt(),
                source_version: Some("1".into()),
            }],
            confidence: Confidence::High,
            observed_at: dt(),
        }
    }
    #[test]
    fn cve_round_trip_is_deterministic() {
        let r = CveRecord {
            id: StableId::new("CVE-2024-1234").unwrap(),
            aliases: vec![],
            descriptions: BTreeMap::from([(String::from("en"), String::from("test"))]),
            cna: None,
            published_at: Some(dt()),
            modified_at: dt(),
            withdrawn_at: None,
            provenance: provenance(),
        };
        r.validate().unwrap();
        let a = serde_json::to_string(&r).unwrap();
        let b = serde_json::to_string(&serde_json::from_str::<CveRecord>(&a).unwrap()).unwrap();
        assert_eq!(a, b);
    }
    #[test]
    fn invalid_id_timestamp_range_and_provenance_rejected() {
        assert!(StableId::new("").is_err());
        assert!(validate_cve_id("CVE-nope", "id").is_err());
        assert!(
            validate_timestamp(DateTime::UNIX_EPOCH - chrono::Duration::seconds(1), "x").is_err()
        );
        assert!(VersionRange {
            introduced: None,
            fixed: None,
            raw: "x".into()
        }
        .validate()
        .is_err());
        assert!(serde_json::from_str::<VersionRange>(
            r#"{"introduced":"1.9","fixed":"1.10","raw":"1.9 < v < 1.10"}"#
        )
        .is_ok());
        assert!(serde_json::from_str::<VersionRange>(
            r#"{"introduced":"1.10","fixed":"1.9","raw":"1.10 < v < 1.9"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<VersionRange>(
            r#"{"introduced":"1.x","fixed":"2.0","raw":"1.x < v < 2.0"}"#
        )
        .is_err());
    }
    #[test]
    fn states_preserve_withdrawn_conflicting_unknown_and_stale() {
        for status in [
            MatchStatus::ConflictingEvidence,
            MatchStatus::Unknown,
            MatchStatus::StaleInventory,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert!(!json.is_empty());
        }
        let cause = TransitionCause::CveWithdrawn;
        assert_eq!(serde_json::to_string(&cause).unwrap(), "\"cve_withdrawn\"");
    }
    #[test]
    fn secrets_and_paths_are_redacted_from_public_serialization() {
        let source = SourceReference {
            source_id: StableId::new("s").unwrap(),
            locator: "/home/private/secret.txt".into(),
            content_sha256: None,
            retrieved_at: dt(),
            source_version: None,
        };
        let serialized = serde_json::to_string(&source).unwrap();
        assert!(!serialized.contains("/home/private"));
        assert!(serialized.contains("redacted-local-locator"));
        let userinfo = SourceReference {
            locator: "https://alice:secret@example.test/a".into(),
            ..source
        };
        let serialized = serde_json::to_string(&userinfo).unwrap();
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("alice:"));
        for locator in [
            "https://example.test/path?token=secret#fragment",
            "file:///home/private/secret.txt",
            "../relative/secret.txt",
        ] {
            let source = SourceReference {
                locator: locator.into(),
                ..userinfo.clone()
            };
            let output = serde_json::to_string(&source).unwrap();
            assert!(!output.contains("secret"));
            assert!(!output.contains(locator));
        }
    }

    #[test]
    fn caller_controlled_redaction_markers_are_replaced() {
        let fake_marker = "[redacted-http-locator: attacker-secret-locator]";
        let source = SourceReference {
            source_id: StableId::new("s").unwrap(),
            locator: fake_marker.into(),
            content_sha256: None,
            retrieved_at: dt(),
            source_version: None,
        };
        let source_output = serde_json::to_string(&source).unwrap();
        assert!(!source_output.contains(fake_marker));
        assert!(source_output.contains("[redacted-locator]"));

        let advisory = AdvisoryRecord {
            id: StableId::new("advisory-marker-test").unwrap(),
            source,
            vendor: "vendor".into(),
            product: "product".into(),
            affected_ranges: vec![VersionRange {
                introduced: Some("1.0".into()),
                fixed: Some("2.0".into()),
                raw: "1.0 < v < 2.0".into(),
            }],
            fixed_versions: vec!["2.0".into()],
            mitigations: vec![],
            references: vec![fake_marker.into()],
            source_version: None,
        };
        let advisory_output = serde_json::to_string(&advisory).unwrap();
        assert_eq!(advisory_output.matches("[redacted-locator]").count(), 2);
        assert!(!advisory_output.contains(fake_marker));
    }

    #[test]
    fn chronology_and_advisory_references_are_validated_and_redacted() {
        let mut record = CveRecord {
            id: StableId::new("CVE-2024-1234").unwrap(),
            aliases: vec![],
            descriptions: BTreeMap::from([(String::from("en"), String::from("test"))]),
            cna: None,
            published_at: Some(dt()),
            modified_at: dt(),
            withdrawn_at: Some(dt() + chrono::Duration::seconds(1)),
            provenance: provenance(),
        };
        assert!(record.validate().is_err());
        record.withdrawn_at = Some(dt());
        assert!(record.validate().is_ok());

        let advisory = AdvisoryRecord {
            id: StableId::new("advisory-1").unwrap(),
            source: SourceReference {
                source_id: StableId::new("vendor").unwrap(),
                locator: "https://internal.example.test/advisories/secret".into(),
                content_sha256: None,
                retrieved_at: dt(),
                source_version: None,
            },
            vendor: "vendor".into(),
            product: "product".into(),
            affected_ranges: vec![VersionRange {
                introduced: Some("1.0".into()),
                fixed: Some("2.0".into()),
                raw: "1.0 < v < 2.0".into(),
            }],
            fixed_versions: vec!["2.0".into()],
            mitigations: vec!["upgrade".into()],
            references: vec![
                "https://internal.example.test/path?token=secret".into(),
                "data:text/plain,secret".into(),
                "file:///home/private/secret".into(),
                "../relative/secret".into(),
            ],
            source_version: None,
        };
        let output = serde_json::to_string(&advisory).unwrap();
        for secret in [
            "internal.example.test",
            "token=secret",
            "data:text",
            "/home/private",
            "../relative",
        ] {
            assert!(!output.contains(secret), "public output leaked {secret}");
        }
        assert_eq!(output.matches("redacted").count(), 5);
    }

    #[test]
    fn malformed_multibyte_cve_ids_are_rejected_without_panicking() {
        for value in [
            "CVE-２０２４-1234",
            "CVE-2024-😀234",
            "CVE-2024-\u{001f}234",
        ] {
            assert!(validate_cve_id(value, "id").is_err());
        }
        assert!(serde_json::from_str::<StableId>("\"bad id\"").is_err());
    }

    #[test]
    fn validated_deserialization_rejects_nested_and_top_level_bypasses() {
        let mut record = serde_json::to_value(CveRecord {
            id: StableId::new("CVE-2024-1234").unwrap(),
            aliases: vec![],
            descriptions: BTreeMap::from([(String::from("en"), String::from("test"))]),
            cna: None,
            published_at: Some(dt()),
            modified_at: dt(),
            withdrawn_at: None,
            provenance: provenance(),
        })
        .unwrap();
        record["provenance"]["references"] = serde_json::json!([]);
        assert!(serde_json::from_value::<CveRecord>(record).is_err());

        let invalid_source = serde_json::json!({
            "source_id": "nvd",
            "locator": "https://example.test/cve.json",
            "content_sha256": "not-a-sha256",
            "retrieved_at": "2024-01-01T00:00:00Z",
            "source_version": "1"
        });
        assert!(serde_json::from_value::<SourceReference>(invalid_source).is_err());

        let invalid_transition = serde_json::json!({
            "id": "transition-1",
            "match_id": "match-1",
            "from": "withdrawn",
            "to": "unknown",
            "cause": "inventory_changed",
            "changed_at": "2024-01-01T00:00:00Z",
            "explanation": "must remain withdrawn",
            "provenance": serde_json::to_value(provenance()).unwrap()
        });
        assert!(serde_json::from_value::<CveStateTransition>(invalid_transition).is_err());
    }
}
