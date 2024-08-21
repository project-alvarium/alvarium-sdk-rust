use crate::errors::{Error, Result};
use crate::providers::hash_provider::{
    HashProviderWrapper, MD5Provider, NoneProvider, Sha256Provider,
};
use alvarium_annotator::constants;

pub fn new_hash_provider(kind: &constants::HashType) -> Result<HashProviderWrapper> {
    if !kind.is_base_hash_type() {
        return Err(Error::NotKnownProvider(kind.0.clone()));
    }

    match kind.0.as_str() {
        "md5" => Ok(HashProviderWrapper::MD5(MD5Provider::new())),
        "sha256" => Ok(HashProviderWrapper::Sha256(Sha256Provider::new())),
        "none" => Ok(HashProviderWrapper::None(NoneProvider::new())),
        _ => Err(Error::NotKnownProvider(kind.0.clone())),
    }
}
