use crate::config::SignatureInfo;
use crate::errors::{Error::NotKnownProvider, Result};
use crate::providers::sign_provider::{Ed25519Provider, SignatureProviderWrap};

pub fn new_signature_provider(config: &SignatureInfo) -> Result<SignatureProviderWrap> {
    if !config.private_key_info.key_type.is_base_key_algorithm() {
        return Err(NotKnownProvider(config.private_key_info.key_type.0.clone()));
    }

    match config.private_key_info.key_type.0.as_str() {
        "ed25519" => Ok(SignatureProviderWrap::Ed25519(Ed25519Provider::new(
            config,
        )?)),
        _ => Err(NotKnownProvider(config.private_key_info.key_type.0.clone())),
    }
}
