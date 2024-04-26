use alvarium_annotator::SignProvider;
use crate::config::SignatureInfo;
use crate::errors::{Error, Result};
use crypto::signatures::ed25519::{
    PublicKey, SecretKey, Signature,
};

pub struct Ed25519Provider {
    public: PublicKey,
    private: SecretKey

}

impl Ed25519Provider {
    pub fn new(config: &SignatureInfo) -> Result<Self> {
        let pub_key_file = std::fs::read(&config.public_key_info.path).unwrap();
        let pub_key_string = String::from_utf8(pub_key_file).unwrap();
        let pk = get_pub_key(&pub_key_string)?;

        let priv_key_file = std::fs::read(&config.private_key_info.path).unwrap();
        let priv_key_string = String::from_utf8(priv_key_file).unwrap();
        let sk = get_priv_key(&priv_key_string)?;

        Ok(Ed25519Provider {
            public: pk,
            private: sk,
        })
    }
}

impl SignProvider for Ed25519Provider {
    type Error = crate::errors::Error;
    fn sign(&self, content: &[u8]) -> Result<String> {
        Ok(hex::encode(self.private.sign(content).to_bytes()))
    }


    fn verify(&self, content: &[u8], signed: &[u8]) -> Result<bool> {
        let sig = get_signature(signed)?;
        Ok(self.public.verify(&sig,content))
    }
}


pub(crate) fn get_priv_key(key: &str) -> Result<SecretKey> {
    let decoded_key = hex::decode(key)?;
    match <[u8;SecretKey::LENGTH]>::try_from(decoded_key.as_slice()) {
        Ok(resized) => Ok(SecretKey::from_bytes(&resized)),
        Err(_) => Err(Error::IncorrectKeySize(decoded_key.len(), SecretKey::LENGTH))
    }
}


pub(crate) fn get_pub_key(key: &str) -> Result<PublicKey> {
    let decoded_key = hex::decode(key)?;
    match <[u8;PublicKey::LENGTH]>::try_from(decoded_key.as_slice()) {
        Ok(resized) => {
            match PublicKey::try_from_bytes(resized) {
                Ok(pub_key) => Ok(pub_key),
                Err(_) => Err(Error::PublicKeyFailure)
            }
        }
        Err(_) => Err(Error::IncorrectKeySize(decoded_key.len(), PublicKey::LENGTH))
    }
}


fn get_signature(signature: &[u8]) -> Result<Signature> {
    match <[u8;Signature::LENGTH]>::try_from(signature) {
        Ok(resized) => Ok(Signature::from_bytes(resized)),
        Err(_) => Err(Error::IncorrectKeySize(signature.len(), Signature::LENGTH))
    }
}