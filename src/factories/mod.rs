mod annotator_factory;
mod hash_factory;
mod signature_factory;
mod stream_factory;

pub use annotator_factory::*;
pub use hash_factory::*;
pub use signature_factory::*;
pub use stream_factory::*;

#[cfg(test)]
mod factory_tests {
    use crate::config::SdkInfo;
    use crate::factories::{
        new_annotator, new_hash_provider, new_signature_provider, new_stream_provider,
    };

    #[tokio::test]
    async fn provider_factory() {
        let sdk_info: SdkInfo = serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();
        let _provider = new_stream_provider(sdk_info.stream).await.unwrap();
    }

    #[tokio::test]
    async fn hasher_factory() {
        let sdk_info: SdkInfo = serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();
        let _provider = new_hash_provider(&sdk_info.hash.hash_type).unwrap();
    }

    #[tokio::test]
    async fn signature_factory() {
        let sdk_info: SdkInfo = serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();
        let _provider = new_signature_provider(&sdk_info.signature).unwrap();
    }

    #[tokio::test]
    async fn annotator_factory() {
        let sdk_info: SdkInfo = serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();
        for ann in &sdk_info.annotators {
            let _annotator = new_annotator(ann.clone(), sdk_info.clone()).unwrap();
        }
    }
}
