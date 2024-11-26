mod md5_provider;
mod none_provider;
mod sha256_provider;

pub use md5_provider::MD5Provider;
pub use none_provider::NoneProvider;
pub use sha256_provider::Sha256Provider;

pub enum HashProviderWrapper {
    MD5(MD5Provider),
    Sha256(Sha256Provider),
    None(NoneProvider),
}

#[async_trait::async_trait]
impl alvarium_annotator::HashProvider for HashProviderWrapper {
    async fn derive(&self, data: &[u8]) -> String {
        match self {
            HashProviderWrapper::MD5(md5) => md5.derive(data).await,
            HashProviderWrapper::Sha256(sha256) => sha256.derive(data).await,
            HashProviderWrapper::None(none) => none.derive(data).await,
        }
    }
}
