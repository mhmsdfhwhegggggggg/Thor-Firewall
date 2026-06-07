use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub interface: String,
    pub log_level: String,
    pub idle_timeout: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            log_level: "info".to_string(),
            idle_timeout: 60,
        }
    }
}

pub fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let config_path = "config.json";
    if let Ok(content) = fs::read_to_string(config_path) {
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    } else {
        Ok(Config::default())
    }
}
