use crate::annotations::{
    Annotation,
    Annotator,
    constants,
};
use crate::{config::{self, Signable}};
use crate::providers::sign_provider::SignatureProviderWrap;
use alvarium_annotator::{derive_hash, serialise_and_sign};
use crate::factories::{new_hash_provider, new_signature_provider};
use crate::errors::{Result, Error};

pub struct PkiAnnotator {
    hash: constants::HashType,
    kind: constants::AnnotationType,
    sign: SignatureProviderWrap,
}

impl PkiAnnotator {
    pub fn new(cfg: &config::SdkInfo) -> Result<impl Annotator<Error = Error>> {
        Ok(PkiAnnotator {
            hash: cfg.hash.hash_type.clone(),
            kind: constants::ANNOTATION_PKI.clone(),
            sign: new_signature_provider(&cfg.signature)?,
        })
    }
}

impl Annotator for PkiAnnotator {
    type Error = crate::errors::Error;
    fn annotate(&mut self, data: &[u8]) -> Result<Annotation> {
        let hasher = new_hash_provider(&self.hash)?;
        let signable: std::result::Result<Signable, serde_json::Error> = serde_json::from_slice(data);
        let (verified, key) = match signable {
            Ok(signable) => {
                let key = derive_hash(hasher, signable.seed.as_bytes());
                (signable.verify_signature(&self.sign)?, key)
            },
            Err(_) => (false, derive_hash(hasher, data)),
        };
        match gethostname::gethostname().to_str() {
            Some(host) => {
                let mut annotation = Annotation::new(&key, self.hash.clone(), host, self.kind.clone(), verified);
                let signature = serialise_and_sign(&self.sign, &annotation)?;
                annotation.with_signature(&signature);
                Ok(annotation)
            },
            None => Err(Error::NoHostName)
        }
    }
}


#[cfg(test)]
mod pki_tests {
    use log::info;
    use crate::{config, providers::sign_provider::get_priv_key};
    use crate::annotations::{Annotator, PkiAnnotator, constants};
    use crate::config::Signable;

    #[test]
    fn valid_and_invalid_pki_annotator() {
        let config: config::SdkInfo = serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();

        let mut config2 = config.clone();
        config2.hash.hash_type = constants::HashType("Not a known hash type".to_string());

        let data = String::from("Some random data");
        let sig = hex::encode([0u8; crypto::signatures::ed25519::SIGNATURE_LENGTH]);

        let signable = Signable::new(data, sig);
        let serialised = serde_json::to_vec(&signable).unwrap();

        let mut pki_annotator_1 = PkiAnnotator::new(&config).unwrap();
        let mut pki_annotator_2 = PkiAnnotator::new(&config2).unwrap();

        let valid_annotation = pki_annotator_1.annotate(&serialised).unwrap();
        let invalid_annotation = pki_annotator_2.annotate(&serialised);

        assert!(valid_annotation.validate_base());
        assert!(invalid_annotation.is_err());
    }


    #[test]
    fn make_pki_annotation() {
        let config: config::SdkInfo = serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();

        info!("config {}", config.signature.private_key_info.path);
        let data = String::from("Some random data");
        let priv_key_file = std::fs::read(&config.signature.private_key_info.path).unwrap();
        let priv_key_string = String::from_utf8(priv_key_file).unwrap();
        let priv_key = get_priv_key(&priv_key_string).unwrap();
        let sig = priv_key.sign(data.as_bytes());

        let signable = Signable::new(data, hex::encode(sig.to_bytes()));
        let serialised = serde_json::to_vec(&signable).unwrap();

        let mut pki_annotator = PkiAnnotator::new(&config).unwrap();
        let annotation = pki_annotator.annotate(&serialised).unwrap();

        assert!(annotation.validate_base());
        assert_eq!(annotation.kind, *constants::ANNOTATION_PKI);
        assert_eq!(annotation.host, gethostname::gethostname().to_str().unwrap());
        assert_eq!(annotation.hash, config.hash.hash_type);
        assert!(annotation.is_satisfied)
    }

    #[test]
    fn unsatisfied_pki_annotation() {
        let config: config::SdkInfo = serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();

        let data = String::from("Some random data");
        let sig = hex::encode([0u8; crypto::signatures::ed25519::SIGNATURE_LENGTH]);

        let signable = Signable::new(data, sig);
        let serialised = serde_json::to_vec(&signable).unwrap();

        let mut pki_annotator = PkiAnnotator::new(&config).unwrap();
        let annotation = pki_annotator.annotate(&serialised).unwrap();

        assert!(annotation.validate_base());
        assert_eq!(annotation.kind, *constants::ANNOTATION_PKI);
        assert_eq!(annotation.host, gethostname::gethostname().to_str().unwrap());
        assert_eq!(annotation.hash, config.hash.hash_type);
        assert!(!annotation.is_satisfied)
    }
}