use alvarium_annotator::constants::{self, LayerType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// TAG_ENV_KEY is an environment key used to associate annotations with specific metadata,
/// aiding in the linkage of scores across different layers of the stack. For instance, in the "app" layer,
/// it is utilized to retrieve the commit SHA of the workload where the application is running,
/// which is instrumental in tracing the impact on the current layer's score from the lower layers.
pub static TAG_ENV_KEY: &'static str = "TAG";

#[derive(Clone, Serialize, Deserialize)]
pub struct TagManager {
    layer: LayerType,
}

impl TagManager {
    pub fn new(layer: LayerType) -> Self {
        Self { layer }
    }

    pub fn get_tag_value(
        &self,
        overrides: Option<HashMap<LayerType, Box<dyn TagWriter>>>,
    ) -> String {
        overrides
            .map(|o| {
                o.get(&self.layer)
                    .map(|s| s.write_tag())
                    .unwrap_or_else(|| self.default_tag_writer())
            })
            .unwrap_or_else(|| self.default_tag_writer())
    }

    pub fn get_tag(&self) -> String {
        self.get_tag_value(None)
    }

    fn default_tag_writer(&self) -> String {
        if self.layer.eq(&constants::LAYER_APP) {
            std::env::var(TAG_ENV_KEY).unwrap_or_default()
        } else {
            "".to_owned()
        }
    }
}

pub trait TagWriter {
    fn write_tag(&self) -> String;
}
