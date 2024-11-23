mod ed25519;

use std::sync::Arc;

use alvarium_annotator::SignProvider;
pub use ed25519::*;

pub type CustomSignatureProvider<T> = Arc<dyn SignProvider<Error = T> + Send + Sync>;

#[derive(Clone)]
pub enum SignatureProviderWrap {
    Ed25519(Ed25519Provider),
    Custom(CustomSignatureProvider<crate::errors::Error>),
}

#[async_trait::async_trait]
impl SignProvider for SignatureProviderWrap {
    type Error = crate::errors::Error;
    async fn sign(&self, content: &[u8]) -> Result<String, Self::Error> {
        match self {
            SignatureProviderWrap::Ed25519(provider) => Ok(provider.sign(content).await?),
            SignatureProviderWrap::Custom(provider) => Ok(provider.sign(content).await?),
        }
    }

    async fn verify(&self, content: &[u8], signed: &[u8]) -> Result<bool, Self::Error> {
        match self {
            SignatureProviderWrap::Ed25519(provider) => {
                Ok(provider.verify(content, signed).await?)
            }
            SignatureProviderWrap::Custom(provider) => Ok(provider.verify(content, signed).await?),
        }
    }
}
