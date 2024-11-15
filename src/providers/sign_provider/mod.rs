mod ed25519;

use std::sync::Arc;

use crate::errors::Result;
use alvarium_annotator::SignProvider;
pub use ed25519::*;

pub type CustomSignatureProvider =
    Box<Arc<dyn SignProvider<Error = crate::errors::Error> + Send + Sync>>;

pub enum SignatureProviderWrap {
    Ed25519(Ed25519Provider),
    Custom(CustomSignatureProvider),
}

#[async_trait::async_trait]
impl alvarium_annotator::SignProvider for SignatureProviderWrap {
    type Error = crate::errors::Error;
    async fn sign(&self, content: &[u8]) -> Result<String> {
        match self {
            SignatureProviderWrap::Ed25519(provider) => Ok(provider.sign(content).await?),
            SignatureProviderWrap::Custom(provider) => Ok(provider.sign(content).await?),
        }
    }

    async fn verify(&self, content: &[u8], signed: &[u8]) -> Result<bool> {
        match self {
            SignatureProviderWrap::Ed25519(provider) => {
                Ok(provider.verify(content, signed).await?)
            }
            SignatureProviderWrap::Custom(provider) => Ok(provider.verify(content, signed).await?),
        }
    }
}
