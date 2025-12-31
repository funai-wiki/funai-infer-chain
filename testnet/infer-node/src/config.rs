use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub node_id: String,
    pub node_address: String,
    pub signer_endpoint: String,
    pub miner_endpoint: String,
    pub supported_models: Vec<String>,
    pub polling_interval_ms: u64,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_ms: u64,
}

fn default_heartbeat_interval() -> u64 {
    30000 // 30 seconds
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}

