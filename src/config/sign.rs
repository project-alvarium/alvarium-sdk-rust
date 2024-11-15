use alvarium_annotator::constants::KeyAlgorithm;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureInfo {
    #[serde(rename = "public")]
    pub public_key_info: KeyInfo,
    pub public_key_stronghold: StrongholdInfo,
    #[serde(rename = "private")]
    pub private_key_info: KeyInfo,
    pub private_key_stronghold: StrongholdInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyInfo {
    #[serde(rename = "type")]
    pub key_type: KeyAlgorithm,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrongholdInfo {
    pub password: KeyAlgorithm,
    pub path: String,
}
