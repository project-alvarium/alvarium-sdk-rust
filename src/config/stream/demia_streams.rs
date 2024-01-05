use serde::{Serialize, Deserialize};
use crate::config::UrlInfo;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DemiaStreamsConfig {
    pub backup: DemiaStreamsBackup,
    pub provider: UrlInfo,
    #[serde(rename="tangle")]
    pub tangle_node: UrlInfo,
    pub encoding: String,
    pub topic: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DemiaStreamsBackup {
    pub path: String,
    pub password: String,
}
