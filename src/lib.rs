extern crate core;

pub mod annotations;
pub mod config;
pub mod errors;
pub mod factories;
pub mod logging;
pub mod providers;
pub mod sdk;

pub type SdkAnnotator = dyn alvarium_annotator::Annotator<Error = crate::errors::Error>;

#[macro_use]
extern crate lazy_static;
// Creates a static CONFIG_BYTES value from the ./config.json file if it exists. If it does not
// it will use the base test_config.json to put into this value
lazy_static! {
    pub static ref CONFIG_BYTES: Vec<u8> = {
        match std::fs::read("config.json") {
            Ok(config_bytes) => config_bytes,
            Err(_) => std::fs::read("resources/test_config.json").unwrap(),
        }
    };
    pub static ref MQTT_TEST_CONFIG_BYTES: Vec<u8> =
        { std::fs::read("resources/mqtt_stream_config.json").unwrap() };
    pub static ref DEMIA_TEST_CONFIG_BYTES: Vec<u8> =
        { std::fs::read("resources/demia_streams_config.json").unwrap() };
}
