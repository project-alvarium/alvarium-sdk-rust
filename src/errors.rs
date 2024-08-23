use thiserror::Error;
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Fern error: {0}")]
    LoggerSetupError(log::SetLoggerError),

    #[error("Logging format error: {0}")]
    LoggerFormattingError(std::io::Error),

    #[error("Failed to deserialize: {0}")]
    DeserializeError(serde_json::Error),

    #[error("HTTP Client error: {0}")]
    HttpClientError(reqwest::Error),

    #[error("Core Alvarium error: {0}")]
    AlvariumCoreError(alvarium_annotator::Error),

    #[error("Not a pre known Alvarium annotator: {0}. Should be built separately")]
    NotKnownProvider(String),

    #[error("Streams Provider error: {0}")]
    StreamsError(streams::Error),

    #[error("Streams LETS error: {0}")]
    StreamsLetsError(streams::LetsError),

    #[error("Mqtt Client error: {0}")]
    MqttClientError(rumqttc::ClientError),

    #[error("Mqtt Connection error: {0}")]
    MqttConnectionError(rumqttc::ConnectionError),

    #[error("Mqtt Connect Return error: {0}")]
    MqttConnectReturnError(String),

    #[error("No Identity present in the user")]
    StreamsNoIdentity,

    #[error("Did not find keyload, subscription may not have been processed correctly")]
    StreamsKeyloadNotFound,

    #[error("Malformed or incorrect configuration provided")]
    IncorrectConfig,

    #[error("Empty signature field")]
    EmptySignature,

    #[error("Could not retrieve host name")]
    NoHostName,

    #[error("Hex decoding failed: {0}")]
    HexDecodeFailure(hex::FromHexError),

    #[error("Array is not the correct size: {0}/{1}")]
    IncorrectKeySize(usize, usize),

    #[error("Failed to make public key from provided bytes")]
    PublicKeyFailure,

    #[error("External error: {0}")]
    External(Box<dyn std::error::Error + Send + Sync>),

    #[error("Backup failed: {0}")]
    BackupFailed(std::io::Error),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::DeserializeError(e)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::HexDecodeFailure(e)
    }
}

impl From<alvarium_annotator::Error> for Error {
    fn from(e: alvarium_annotator::Error) -> Self {
        Error::AlvariumCoreError(e)
    }
}

impl From<streams::Error> for Error {
    fn from(e: streams::Error) -> Self {
        Error::StreamsError(e)
    }
}

impl From<rumqttc::ClientError> for Error {
    fn from(e: rumqttc::ClientError) -> Self {
        Error::MqttClientError(e)
    }
}

impl From<rumqttc::ConnectionError> for Error {
    fn from(e: rumqttc::ConnectionError) -> Self {
        Error::MqttConnectionError(e)
    }
}

impl From<rumqttc::ConnectReturnCode> for Error {
    fn from(e: rumqttc::ConnectReturnCode) -> Self {
        Error::MqttConnectReturnError(format!("{:?}", e))
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::HttpClientError(e)
    }
}

impl From<streams::LetsError> for Error {
    fn from(e: streams::LetsError) -> Self {
        Error::StreamsLetsError(e)
    }
}
