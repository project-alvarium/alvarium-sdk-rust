use serde::{Serialize, Deserialize};
use crate::config::{HashInfo, SignatureInfo, StreamInfo};
use crate::annotations::constants::AnnotationType;


fn level_info() -> String {
    "info".to_string()
}
fn debug_location() -> String {
    "log.out".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SdkInfo {
    pub annotators: Vec<AnnotationType>,
    pub hash: HashInfo,
    pub signature: SignatureInfo,
    pub stream: StreamInfo,
    #[serde(default)]
    pub logging: LoggingConfiguration,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoggingConfiguration {
    #[serde(default = "level_info")]
    pub level: String,
    #[serde(default = "debug_location")]
    pub debug_location: String,
}
