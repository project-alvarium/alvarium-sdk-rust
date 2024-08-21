use crate::config::UrlInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MqttStreamConfig {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "boundedCap")]
    pub cap: usize,
    #[serde(rename = "keepAlive")]
    pub keep_alive: u8,
    pub qos: u8,
    pub user: String,
    password: String,
    pub provider: UrlInfo,
    pub cleanness: bool,
    pub topics: Vec<String>,
}

impl MqttStreamConfig {
    pub(crate) fn password(&self) -> &str {
        &self.password
    }
}
