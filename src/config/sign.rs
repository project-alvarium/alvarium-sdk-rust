use alvarium_annotator::constants::KeyAlgorithm;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureInfo {
    #[serde(rename="public")]
    pub public_key_info: KeyInfo,
    #[serde(rename="private")]
    pub private_key_info: KeyInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyInfo {
    #[serde(rename="type")]
    pub key_type: KeyAlgorithm,
    pub path: String
}