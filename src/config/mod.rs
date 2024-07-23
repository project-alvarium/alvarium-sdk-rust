mod hash;
mod sdk;
mod sign;
mod stream;

pub use hash::*;
pub use sdk::*;
pub use sign::*;
pub use stream::*;

#[cfg(test)]
mod make_config_tests {
    use super::{DemiaStreamsConfig, MqttStreamConfig, SdkInfo, StreamInfo};
    #[test]
    fn new_config() {
        let config: SdkInfo = serde_json::from_slice(crate::CONFIG_BYTES.as_slice()).unwrap();
        assert!(config.hash.hash_type.is_base_hash_type());
        assert!(config
            .signature
            .private_key_info
            .key_type
            .is_base_key_algorithm());
        assert!(config.annotators[0].is_base_annotation_type());
    }

    #[test]
    fn demia_streams_config() {
        let config: StreamInfo =
            serde_json::from_slice(crate::DEMIA_TEST_CONFIG_BYTES.as_slice()).unwrap();
        let _is_config: DemiaStreamsConfig;
        assert!(config.stream_type.is_base_stream_type());
        assert!(matches!(config.config, _is_config));
    }

    #[test]
    fn mqtt_stream_config() {
        let config: StreamInfo =
            serde_json::from_slice(crate::MQTT_TEST_CONFIG_BYTES.as_slice()).unwrap();
        let _mqtt_config: MqttStreamConfig;
        assert!(config.stream_type.is_base_stream_type());
        assert!(matches!(config.config, _mqtt_config));
    }
}
