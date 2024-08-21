use crate::annotations::constants::AnnotationType;
use crate::config::{HashInfo, SignatureInfo, StreamInfo};
use alvarium_annotator::constants::LayerType;
use serde::{Deserialize, Serialize};

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
    pub layer: LayerType,
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
