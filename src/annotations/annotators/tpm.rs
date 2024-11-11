use crate::annotations::{constants, Annotation, Annotator};
use crate::config;
use crate::errors::{Error, Result};
use crate::managers::tag_manager::TagManager;
use alvarium_annotator::constants::LayerType;
use alvarium_annotator::{derive_hash, serialise_and_sign};

use crate::config::Signable;
use crate::factories::{new_hash_provider, new_signature_provider};
use crate::providers::sign_provider::SignatureProviderWrap;
#[cfg(unix)]
use std::os::linux::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

const UNIX_TPM_PATH: &str = "/dev/tpm0"; // Adjust the path as needed

pub struct TpmAnnotator {
    hash: constants::HashType,
    kind: constants::AnnotationType,
    sign: SignatureProviderWrap,
    layer: LayerType,
    tag_manager: TagManager,
}

impl TpmAnnotator {
    pub fn new(cfg: &config::SdkInfo) -> Result<impl Annotator<Error = Error>> {
        Ok(TpmAnnotator {
            hash: cfg.hash.hash_type.clone(),
            kind: constants::ANNOTATION_TPM.clone(),
            sign: new_signature_provider(&cfg.signature)?,
            layer: cfg.layer.clone(),
            tag_manager: TagManager::new(cfg.layer.clone()),
        })
    }

    #[cfg(windows)]
    fn check_tpm_presence_windows() -> bool {
        let output = std::process::Command::new("tpmtool")
            .arg("getdeviceinformation")
            .output();

        match output {
            Ok(output) => {
                // Check if the tpmtool command executed successfully and contains "TPM Present"
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("TPM Present: Yes")
            }
            Err(_) => false,
        }
    }

    #[cfg(unix)]
    fn check_tpm_presence_unix(&self) -> bool {
        match std::fs::metadata(UNIX_TPM_PATH) {
            Ok(metadata) => {
                let file_type = metadata.st_mode() & libc::S_IFMT;
                file_type == libc::S_IFCHR || file_type == libc::S_IFSOCK
            }
            Err(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl Annotator for TpmAnnotator {
    type Error = crate::errors::Error;
    async fn execute(&mut self, data: &[u8]) -> Result<Annotation> {
        let hasher = new_hash_provider(&self.hash)?;
        let signable: std::result::Result<Signable, serde_json::Error> =
            serde_json::from_slice(data);
        let key = match signable {
            Ok(signable) => derive_hash(hasher, signable.seed.as_bytes()).await,
            Err(_) => derive_hash(hasher, data).await,
        };
        match gethostname::gethostname().to_str() {
            Some(host) => {
                #[cfg(unix)]
                let is_satisfied = self.check_tpm_presence_unix();
                #[cfg(windows)]
                let is_satisfied = self.check_tpm_presence_windows();

                let mut annotation = Annotation::new(
                    &key,
                    self.hash.clone(),
                    host,
                    self.layer.clone(),
                    self.kind.clone(),
                    is_satisfied,
                    None,
                );
                annotation.set_tag(self.tag_manager.get_tag());
                let signature = serialise_and_sign(&self.sign, &annotation).await?;
                annotation.with_signature(&signature);
                Ok(annotation)
            }
            None => Err(Error::NoHostName),
        }
    }
}

#[cfg(test)]
mod tpm_tests {
    #[cfg(unix)]
    use super::UNIX_TPM_PATH;
    use crate::annotations::{constants, Annotator, TpmAnnotator};
    use crate::config::Signable;
    use crate::{config, providers::sign_provider::get_priv_key};

    #[tokio::test]
    async fn valid_and_invalid_tpm_annotator() {
        let config: config::SdkInfo =
            serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();

        let mut config2 = config.clone();
        config2.hash.hash_type = constants::HashType("Not a known hash type".to_string());

        let data = String::from("Some random data");
        let sig = hex::encode([0u8; crypto::signatures::ed25519::Signature::LENGTH]);

        let signable = Signable::new(data, sig);
        let serialised = serde_json::to_vec(&signable).unwrap();

        let mut tpm_annotator_1 = TpmAnnotator::new(&config).unwrap();
        let mut tpm_annotator_2 = TpmAnnotator::new(&config2).unwrap();

        let valid_annotation = tpm_annotator_1.execute(&serialised).await.unwrap();
        let invalid_annotation = tpm_annotator_2.execute(&serialised).await;

        assert!(valid_annotation.validate_base());
        assert!(invalid_annotation.is_err());
    }

    #[tokio::test]
    async fn make_tpm_annotation() {
        let config: config::SdkInfo =
            serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();

        let data = String::from("Some random data");
        let priv_key_file = std::fs::read(&config.signature.private_key_info.path).unwrap();
        let priv_key_string = String::from_utf8(priv_key_file).unwrap();
        let priv_key = get_priv_key(&priv_key_string).unwrap();
        let sig = priv_key.sign(data.as_bytes());

        let signable = Signable::new(data, hex::encode(sig.to_bytes()));
        let serialised = serde_json::to_vec(&signable).unwrap();

        let mut tpm_annotator = TpmAnnotator::new(&config).unwrap();
        let annotation = tpm_annotator.execute(&serialised).await.unwrap();

        assert!(annotation.validate_base());
        assert_eq!(annotation.kind, *constants::ANNOTATION_TPM);
        assert_eq!(
            annotation.host,
            gethostname::gethostname().to_str().unwrap()
        );
        assert_eq!(annotation.hash, config.hash.hash_type);

        #[cfg(unix)]
        let should_be_satisfied = std::fs::metadata(UNIX_TPM_PATH).is_ok();
        #[cfg(windows)]
        let should_be_satisfied = {
            let output = std::process::Command::new("tpmtool")
                .arg("getdeviceinformation")
                .output();
            match output {
                Ok(output) => {
                    output.status.success()
                        && String::from_utf8_lossy(&output.stdout).contains("TPM Present: Yes")
                }
                Err(_) => false,
            }
        };

        assert_eq!(annotation.is_satisfied, should_be_satisfied);
    }
}
