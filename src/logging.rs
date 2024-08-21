// src/logger/mod.rs

use crate::config::SdkInfo;
use crate::errors::{Error, Result};
use log::LevelFilter;

pub fn init(config: &SdkInfo) -> Result<()> {
    let log_level = match config.logging.level.as_str() {
        "debug" => LevelFilter::Debug,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };

    fern::Dispatch::new()
        .format(|out, message, record| {
            let source = format!("{}:{}", record.target(), record.line().unwrap_or_default());
            let gap = if source.len() < 35 {
                " ".repeat(35 - source.len())
            } else {
                " ".to_string()
            };

            out.finish(format_args!(
                "[{} | {:6}| {}]{} {}",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                source,
                gap,
                message
            ))
        })
        .level(log_level)
        .chain(std::io::stdout())
        .apply()
        .map_err(Error::LoggerSetupError)?;
    Ok(())
}
