mod demia;
mod mqtt;

pub use demia::DemiaPublisher;
pub use mqtt::MqttPublisher;


// TODO: Implement publisher for enum
pub enum PublisherWrap {
    Demia(DemiaPublisher),
    Mqtt(MqttPublisher),
}
