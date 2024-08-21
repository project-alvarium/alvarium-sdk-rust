use crate::annotations::constants::HashType;
use alvarium_annotator::constants::Validate;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HashInfo {
    #[serde(rename = "type")]
    pub hash_type: HashType,
}

impl Validate for HashInfo {
    fn validate(&self) -> bool {
        self.hash_type.is_base_hash_type()
    }
}
