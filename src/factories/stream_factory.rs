use crate::config::{StreamConfig, StreamInfo};
use crate::errors::Result;
use crate::providers::stream_provider::{DemiaPublisher, MqttPublisher, PublisherWrap};
use alvarium_annotator::Publisher;

pub async fn new_stream_provider(cfg: StreamInfo) -> Result<PublisherWrap> {
    match cfg.config {
        StreamConfig::DemiaStreams(_) => {
            let publisher = DemiaPublisher::new(&cfg).await?;
            Ok(PublisherWrap::Demia(publisher))
        }
        StreamConfig::MQTT(_) => {
            let publisher = MqttPublisher::new(&cfg).await?;
            Ok(PublisherWrap::Mqtt(publisher))
        }
    }
}
