use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Point-in-time operational statistics for Starmetal.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct StatisticsSnapshot {
    pub ecosystems: BTreeMap<String, EcosystemStatistics>,
}

/// In-memory cache and operation counters for one ecosystem.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct EcosystemStatistics {
    pub versions_cache_hits: u64,
    pub versions_cache_misses: u64,
    pub metadata_cache_hits: u64,
    pub metadata_cache_misses: u64,
    pub artifact_cache_hits: u64,
    pub artifact_cache_misses: u64,
    pub bytes_served: u64,
    pub upstream_errors: u64,
    pub publishes: u64,
    pub yanks: u64,
    pub integrity_failures: u64,
    pub last_activity_unix_seconds: Option<u64>,
}
