use crate::config::UrlInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DemiaStreamsConfig {
    pub backup: DemiaStreamsBackup,
    pub provider: UrlInfo,
    #[serde(rename = "tangle")]
    pub tangle_node: UrlInfo,
    pub encoding: String,
    pub topic: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DemiaStreamsBackup {
    pub path: String,
    pub password: String,
}
