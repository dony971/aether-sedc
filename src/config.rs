use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
            data_dir: PathBuf::from("./data"),
            p2p_port: 25565,
            rpc_port: 9933,
            bootnodes: Vec::new(),
            dns_seeds: vec![
                "seed.aether.network".into(),
                "seed1.aether.network".into(),
            ],
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
