use crate::annotations::{constants, Annotation, Annotator};
use crate::config;
use crate::config::Signable;
use crate::errors::{Error, Result};
use crate::factories::{new_hash_provider, new_signature_provider};
use crate::providers::sign_provider::SignatureProviderWrap;
use alvarium_annotator::constants::LayerType;
use alvarium_annotator::{derive_hash, serialise_and_sign};

pub struct SourceAnnotator {
    hash: constants::HashType,
    kind: constants::AnnotationType,
    sign: SignatureProviderWrap,
    layer: LayerType,
}

impl SourceAnnotator {
    pub fn new(cfg: &config::SdkInfo) -> Result<impl Annotator<Error = Error>> {
        Ok(SourceAnnotator {
            hash: cfg.hash.hash_type.clone(),
            kind: constants::ANNOTATION_SOURCE.clone(),
            sign: new_signature_provider(&cfg.signature)?,
            layer: cfg.layer.clone(),
        })
    }
}

impl Annotator for SourceAnnotator {
    type Error = crate::errors::Error;
    fn execute(&mut self, data: &[u8]) -> Result<Annotation> {
        let hasher = new_hash_provider(&self.hash)?;
        let signable: std::result::Result<Signable, serde_json::Error> =
            serde_json::from_slice(data);
        let key = match signable {
            Ok(signable) => derive_hash(hasher, signable.seed.as_bytes()),
            Err(_) => derive_hash(hasher, data),
        };
        match gethostname::gethostname().to_str() {
            Some(host) => {
                let mut annotation = Annotation::new(
                    &key,
                    self.hash.clone(),
                    host,
                    self.layer.clone(),
                    self.kind.clone(),
                    true,
                );
                let signature = serialise_and_sign(&self.sign, &annotation)?;
                annotation.with_signature(&signature);
                Ok(annotation)
            }
            None => Err(Error::NoHostName),
        }
    }
}

#[cfg(test)]
mod source_tests {
    use crate::annotations::{constants, Annotator, SourceAnnotator};
    use crate::config::Signable;
    use crate::{config, providers::sign_provider::get_priv_key};

    #[test]
    fn valid_and_invalid_source_annotator() {
        let config: config::SdkInfo =
            serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();

        let mut config2 = config.clone();
        config2.hash.hash_type = constants::HashType("Not a known hash type".to_string());

        let data = String::from("Some random data");
        let sig = hex::encode([0u8; crypto::signatures::ed25519::SIGNATURE_LENGTH]);

        let signable = Signable::new(data, sig);
        let serialised = serde_json::to_vec(&signable).unwrap();

        let mut source_annotator_1 = SourceAnnotator::new(&config).unwrap();
        let mut source_annotator_2 = SourceAnnotator::new(&config2).unwrap();
        let valid_annotation = source_annotator_1.execute(&serialised).unwrap();
        let invalid_annotation = source_annotator_2.execute(&serialised);

        assert!(valid_annotation.validate_base());
        assert!(invalid_annotation.is_err());
    }

    #[test]
    fn make_source_annotation() {
        let config: config::SdkInfo =
            serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();

        let data = String::from("Some random data");
        let priv_key_file = std::fs::read(&config.signature.private_key_info.path).unwrap();
        let priv_key_string = String::from_utf8(priv_key_file).unwrap();
        let priv_key = get_priv_key(&priv_key_string).unwrap();
        let sig = priv_key.sign(data.as_bytes());

        let signable = Signable::new(data, hex::encode(sig.to_bytes()));
        let serialised = serde_json::to_vec(&signable).unwrap();

        let mut source_annotator = SourceAnnotator::new(&config).unwrap();
        let annotation = source_annotator.execute(&serialised).unwrap();

        assert!(annotation.validate_base());
        assert_eq!(annotation.kind, *constants::ANNOTATION_SOURCE);
        assert_eq!(
            annotation.host,
            gethostname::gethostname().to_str().unwrap()
        );
        assert_eq!(annotation.hash, config.hash.hash_type);
        assert!(annotation.is_satisfied)
    }
}
