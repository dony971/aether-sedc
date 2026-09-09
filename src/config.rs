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
    /// RPC bind address. Secure-by-default loopback (phase n°7 hardening):
    /// the RPC server only listens on loopback unless the operator
    /// explicitly sets a non-loopback address (CLI --rpc-bind or TOML).
    /// INFRASTRUCTURE hardening — no consensus/DAG/ledger impact.
    pub rpc_bind: String,
    pub bootnodes: Vec<String>,
    pub dns_seeds: Vec<String>,
    pub miner_address: Option<String>,
    pub reset: bool,
    pub repair_ledger: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_type: "miner".into(),
            data_dir: default_data_dir(),
            p2p_port: 25565,
            rpc_port: 9933,
            rpc_bind: "127.0.0.1".into(),
            bootnodes: vec!["103.102.135.123:25565".to_string()],
            dns_seeds: Vec::new(),
            miner_address: None,
            reset: false,
            repair_ledger: false,
        }
    }
}

impl NodeConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: NodeConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// INFRASTRUCTURE (n°7): true when the RPC bind is loopback-only.
    pub fn rpc_is_loopback(&self) -> bool {
        let b = self.rpc_bind.trim().to_lowercase();
        b == "127.0.0.1" || b == "::1" || b == "localhost"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RPC-01: secure by default — fresh config binds loopback, and old
    /// TOML files without the field still parse (serde default) as loopback.
    #[test]
    fn test_rpc_bind_defaults_loopback() {
        let cfg = NodeConfig::default();
        assert_eq!(cfg.rpc_bind, "127.0.0.1");
        assert!(cfg.rpc_is_loopback());
        // Old TOML files without the field still parse (serde default).
        let cfg2: NodeConfig = toml::from_str(
            "node_type = \"miner\"\ndata_dir = \"./data\"\np2p_port = 25565\nrpc_port = 9933\nbootnodes = []\ndns_seeds = []\n",
        )
        .expect("legacy TOML without rpc_bind must parse");
        assert_eq!(cfg2.rpc_bind, "127.0.0.1");
        assert!(cfg2.rpc_is_loopback());
        let mut open = NodeConfig::default();
        open.rpc_bind = "0.0.0.0".into();
        assert!(!open.rpc_is_loopback());
    }
}
