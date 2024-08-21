mod demia_streams;
mod mqtt;

use alvarium_annotator::{SignProvider, StreamConfigWrapper};
pub use demia_streams::*;
pub use mqtt::*;

use serde::{Deserialize, Serialize};

use crate::annotations::constants::StreamType;
use crate::errors::{Error, Result};
use crate::providers::sign_provider::SignatureProviderWrap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamInfo {
    #[serde(rename = "type")]
    pub stream_type: StreamType,
    pub config: StreamConfig,
}

impl StreamConfigWrapper for StreamInfo {
    fn stream_type(&self) -> &StreamType {
        &self.stream_type
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UrlInfo {
    pub host: String,
    pub port: usize,
    pub protocol: String,
}

impl UrlInfo {
    pub fn uri(&self) -> String {
        format!("{}://{}:{}", self.protocol, self.host, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StreamConfig {
    DemiaStreams(DemiaStreamsConfig),
    MQTT(MqttStreamConfig),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signable {
    pub seed: String,
    pub signature: String,
}

impl Signable {
    pub fn new(seed: String, signature: String) -> Self {
        Signable { seed, signature }
    }

    pub fn verify_signature(&self, provider: &SignatureProviderWrap) -> Result<bool> {
        if self.signature.is_empty() {
            return Err(Error::EmptySignature);
        }

        match provider {
            SignatureProviderWrap::Ed25519(provider) => {
                let sig_bytes = hex::decode(&self.signature)?;
                Ok(provider.verify(self.seed.as_bytes(), &sig_bytes)?)
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Strings should not fail to serde
        // TODO: Verify that this is the case
        serde_json::to_vec(&self).unwrap()
    }
}

#[cfg(test)]
mod config_tests {
    use super::Signable;
    use crate::config;
    use crate::providers::sign_provider::{Ed25519Provider, SignatureProviderWrap};
    use alvarium_annotator::SignProvider;
    use crypto::signatures::ed25519::SecretKey;

    #[tokio::test]
    async fn verify_signable() {
        let config: config::SdkInfo =
            serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();
        let sig_provider =
            SignatureProviderWrap::Ed25519(Ed25519Provider::new(&config.signature).unwrap());

        let data = "A data packet to sign".to_string();
        let sig = sig_provider.sign(data.as_bytes()).unwrap();

        let signable = Signable {
            seed: data,
            signature: sig,
        };

        assert!(signable.verify_signature(&sig_provider).unwrap())
    }

    #[test]
    fn failed_verification_signable() {
        let config: config::SdkInfo =
            serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();
        let bad_priv_key = SecretKey::generate().unwrap();

        let data = "A data packet to sign".to_string();
        let raw_sig = bad_priv_key.sign(data.as_bytes());

        let signable = Signable {
            seed: data,
            signature: hex::encode(raw_sig.to_bytes()),
        };

        let sig_provider =
            SignatureProviderWrap::Ed25519(Ed25519Provider::new(&config.signature).unwrap());

        assert!(!signable.verify_signature(&sig_provider).unwrap())
    }
}
