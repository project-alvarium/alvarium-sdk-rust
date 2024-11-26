mod demia;
mod mqtt;

use crate::config::StreamInfo;
use alvarium_annotator::{MessageWrapper, Publisher};
pub use demia::DemiaPublisher;
pub use mqtt::MqttPublisher;

// TODO: Implement publisher for enum
pub enum PublisherWrap {
    Demia(DemiaPublisher),
    Mqtt(MqttPublisher),
}

#[async_trait::async_trait]
impl Publisher for PublisherWrap {
    type StreamConfig = StreamInfo;
    type Error = crate::errors::Error;

    async fn new(cfg: &Self::StreamConfig) -> Result<Self, Self::Error> {
        crate::factories::new_stream_provider(cfg.clone()).await
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Demia(p) => p.close().await,
            Self::Mqtt(p) => p.close().await,
        }
    }

    async fn connect(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Demia(p) => p.connect().await,
            Self::Mqtt(p) => p.connect().await,
        }
    }

    async fn reconnect(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Demia(p) => p.reconnect().await,
            Self::Mqtt(p) => p.reconnect().await,
        }
    }

    async fn publish(&mut self, msg: MessageWrapper<'_>) -> Result<(), Self::Error> {
        match self {
            Self::Demia(p) => p.publish(msg).await,
            Self::Mqtt(p) => p.publish(msg).await,
        }
    }
}
