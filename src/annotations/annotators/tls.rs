use crate::annotations::{constants, Annotation, Annotator};
use crate::config;
use crate::errors::{Error, Result};
use crate::managers::tag_manager::TagManager;
use alvarium_annotator::constants::LayerType;
use alvarium_annotator::{derive_hash, serialise_and_sign};
#[cfg(feature = "rustls")]
use std::io::Read;

use crate::config::Signable;
use crate::factories::{new_hash_provider, new_signature_provider};
use crate::providers::sign_provider::SignatureProviderWrap;
use log::info;
#[cfg(feature = "native-tls")]
use native_tls::TlsStream;
#[cfg(feature = "rustls")]
use rustls::Connection;
use std::net::TcpStream;
#[cfg(feature = "native-tls")]
use std::sync::Mutex;

pub struct TlsAnnotator {
    hash: constants::HashType,
    kind: constants::AnnotationType,
    sign: SignatureProviderWrap,
    layer: LayerType,
    tag_manager: TagManager,

    // TODO: Make type for this
    #[cfg(feature = "native-tls")]
    conn_native: Option<Mutex<TlsStream<TcpStream>>>,

    #[cfg(feature = "rustls")]
    conn_rustls: Option<Connection>,
    #[cfg(feature = "rustls")]
    stream: Option<TcpStream>,
}

impl TlsAnnotator {
    pub fn new(cfg: &config::SdkInfo) -> Result<impl Annotator<Error = Error> + Tls> {
        Ok(TlsAnnotator {
            hash: cfg.hash.hash_type.clone(),
            kind: constants::ANNOTATION_TLS.clone(),
            sign: new_signature_provider(&cfg.signature)?,
            tag_manager: TagManager::new(cfg.layer.clone()),
            layer: cfg.layer.clone(),
            #[cfg(feature = "native-tls")]
            conn_native: None,
            #[cfg(feature = "rustls")]
            conn_rustls: None,
            #[cfg(feature = "rustls")]
            stream: None,
        })
    }

    pub fn new_with_provider(
        cfg: &config::SdkInfo,
        sign_provider: SignatureProviderWrap,
    ) -> Result<impl Annotator<Error = Error>> {
        Ok(TlsAnnotator {
            hash: cfg.hash.hash_type.clone(),
            kind: constants::ANNOTATION_TLS.clone(),
            sign: sign_provider,
            tag_manager: TagManager::new(cfg.layer.clone()),
            layer: cfg.layer.clone(),
            #[cfg(feature = "native-tls")]
            conn_native: None,
            #[cfg(feature = "rustls")]
            conn_rustls: None,
            #[cfg(feature = "rustls")]
            stream: None,
        })
    }
}

pub trait Tls {
    #[cfg(feature = "native-tls")]
    fn set_connection_native(&mut self, tls_stream: TlsStream<TcpStream>);
    #[cfg(feature = "rustls")]
    fn set_connection_rustls(&mut self, conn: Connection, stream: TcpStream);

    #[cfg(feature = "native-tls")]
    fn check_tls_stream_native(&self) -> bool;
    #[cfg(feature = "rustls")]
    fn check_tls_stream_rustls(&mut self) -> bool;
}

impl Tls for TlsAnnotator {
    #[cfg(feature = "native-tls")]
    fn set_connection_native(&mut self, tls_stream: TlsStream<TcpStream>) {
        self.conn_native = Some(Mutex::new(tls_stream));
    }

    #[cfg(feature = "rustls")]
    fn set_connection_rustls(&mut self, conn: Connection, stream: TcpStream) {
        self.stream = Some(stream);
        self.conn_rustls = Some(conn);
    }

    #[cfg(feature = "native-tls")]
    fn check_tls_stream_native(&self) -> bool {
        match &self.conn_native {
            Some(conn) => conn.lock().unwrap().peer_certificate().is_ok(),
            None => false,
        }
    }

    #[cfg(feature = "rustls")]
    fn check_tls_stream_rustls(&mut self) -> bool {
        if let Some(stream) = self.stream.as_mut() {
            info!("Stream exists");
            if let Some(conn) = self.conn_rustls.as_mut() {
                info!("Connection exists");
                let mut buf = [0; 1024];
                let mut retries = 0;

                loop {
                    if conn.wants_write() {
                        conn.write_tls(stream).unwrap();
                    }

                    if conn.wants_read() {
                        if stream.read(&mut buf).unwrap() == 0 {
                            break;
                        }
                        conn.read_tls(stream).unwrap();
                    }

                    if !conn.is_handshaking() {
                        break;
                    } else {
                        retries += 1;
                        if retries == 5 {
                            return false;
                        }
                    }
                }

                let mut buffer = [0; 1];
                match stream.peek(&mut buffer) {
                    Ok(_) => true,
                    Err(e) => match e.kind() {
                        std::io::ErrorKind::WouldBlock => true,
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
                            info!("Connection error in TLS stream: {:?}", e);
                            false
                        }
                        _ => {
                            info!("Unexpected error in TLS stream: {:?}", e);
                            false
                        }
                    },
                }
            } else {
                false
            }
        } else {
            false
        }
    }
}

// Create a TLS Server Connection instance to determine if it is being used
#[async_trait::async_trait]
impl Annotator for TlsAnnotator {
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
                #[cfg(all(not(feature = "rustls"), feature = "native-tls"))]
                let is_satisfied = self.check_tls_stream_native();
                #[cfg(feature = "rustls")]
                let is_satisfied = self.check_tls_stream_rustls();

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
mod tls_tests {
    #[cfg(feature = "rustls")]
    use super::Tls;
    use crate::annotations::{constants, Annotator, TlsAnnotator};
    use crate::config::Signable;
    use crate::{config, providers::sign_provider::get_priv_key};
    use rustls::ClientConnection;
    use std::net::TcpStream;
    use std::sync::Arc;

    #[tokio::test]
    async fn valid_and_invalid_tls_annotator() {
        let config: config::SdkInfo =
            serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();

        let mut config2 = config.clone();
        config2.hash.hash_type = constants::HashType("Not a known hash type".to_string());

        let data = String::from("Some random data");
        let sig = hex::encode([0u8; crypto::signatures::ed25519::Signature::LENGTH]);

        let signable = Signable::new(data, sig);
        let serialised = serde_json::to_vec(&signable).unwrap();

        let mut tls_annotator_1 = TlsAnnotator::new(&config).unwrap();
        let mut tls_annotator_2 = TlsAnnotator::new(&config2).unwrap();

        let valid_annotation = tls_annotator_1.execute(&serialised).await.unwrap();
        let invalid_annotation = tls_annotator_2.execute(&serialised).await;

        assert!(valid_annotation.validate_base());
        assert!(invalid_annotation.is_err());
    }

    #[cfg(feature = "rustls")]
    #[tokio::test]
    async fn make_tls_annotation() {
        let config: config::SdkInfo =
            serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();

        let data = String::from("Some random data");
        let priv_key_file = std::fs::read(&config.signature.private_key_info.path).unwrap();
        let priv_key_string = String::from_utf8(priv_key_file).unwrap();
        let priv_key = get_priv_key(&priv_key_string).unwrap();
        let sig = priv_key.sign(data.as_bytes());

        let signable = Signable::new(data, hex::encode(sig.to_bytes()));
        let serialised = serde_json::to_vec(&signable).unwrap();

        let mut tls_annotator = TlsAnnotator::new(&config).unwrap();

        let conn = make_client_connection().unwrap();
        let tcp_stream = TcpStream::connect("www.google.com:443").unwrap();
        tls_annotator.set_connection_rustls(conn.into(), tcp_stream);

        let annotation = tls_annotator.execute(&serialised).await.unwrap();

        assert!(annotation.validate_base());
        assert_eq!(annotation.kind, *constants::ANNOTATION_TLS);
        assert_eq!(
            annotation.host,
            gethostname::gethostname().to_str().unwrap()
        );
        assert_eq!(annotation.hash, config.hash.hash_type);
        assert!(annotation.is_satisfied)
    }

    #[tokio::test]
    async fn unsatisfied_tls_annotation() {
        let config: config::SdkInfo =
            serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();

        let data = String::from("Some random data");
        let sig = hex::encode([0u8; crypto::signatures::ed25519::Signature::LENGTH]);

        let signable = Signable::new(data, sig);
        let serialised = serde_json::to_vec(&signable).unwrap();

        let mut tls_annotator = TlsAnnotator::new(&config).unwrap();
        let annotation = tls_annotator.execute(&serialised).await.unwrap();

        assert!(annotation.validate_base());
        assert_eq!(annotation.kind, *constants::ANNOTATION_TLS);
        assert_eq!(
            annotation.host,
            gethostname::gethostname().to_str().unwrap()
        );
        assert_eq!(annotation.hash, config.hash.hash_type);
        assert!(!annotation.is_satisfied)
    }

    #[cfg(feature = "rustls")]
    fn make_client_connection() -> Result<ClientConnection, Box<dyn std::error::Error>> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let config = rustls::ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name = "www.google.com".try_into().unwrap();
        Ok(ClientConnection::new(Arc::new(config), server_name).unwrap())
    }
}
