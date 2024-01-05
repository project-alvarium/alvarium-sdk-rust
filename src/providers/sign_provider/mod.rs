mod ed25519;

use crate::errors::Result;
pub use ed25519::*;

pub enum SignatureProviderWrap {
    Ed25519(Ed25519Provider)
}

impl alvarium_annotator::SignProvider for SignatureProviderWrap {
    type Error = crate::errors::Error;
    fn sign(&self, content: &[u8]) -> Result<String> {
        match self {
            SignatureProviderWrap::Ed25519(provider) => Ok(provider.sign(content)?)
        }
    }

    fn verify(&self, content: &[u8], signed: &[u8]) -> Result<bool> {
        match self {
            SignatureProviderWrap::Ed25519(provider) => Ok(provider.verify(content, signed)?)
        }
    }

}