use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub fn default_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let mut path = PathBuf::from(appdata);
            path.push("Aether");
            return path;
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let mut path = PathBuf::from(home);
            path.push("Library/Application Support/Aether");
            return path;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let mut path = PathBuf::from(home);
            path.push(".aether");
            return path;
        }
    }
    PathBuf::from("./data")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    pub node_type: String,
    pub data_dir: PathBuf,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub bootnodes: Vec<String>,
    pub dns_seeds: Vec<String>,
    pub miner_address: Option<String>,
    pub reset: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_type: "miner".into(),
            data_dir: default_data_dir(),
            p2p_port: 25565,
            rpc_port: 9933,
            bootnodes: vec!["103.102.135.123:25565".to_string()],
            dns_seeds: Vec::new(),
            miner_address: None,
            reset: false,
        }
    }
}

impl NodeConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: NodeConfig = toml::from_str(&content)?;
        Ok(config)
    }
}
