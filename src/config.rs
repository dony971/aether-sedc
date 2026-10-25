use crate::p2p::P2PProtocolMode;
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
    /// PHASE 4V: V6 network identity (legacy default 0 when mapped).
    /// PHASE 4X: Option to distinguish UNSET (absent: legacy V5 path, V6
    /// forbidden) from EXPLICITLY_SET (Some, including Some(0) = explicitly
    /// legacy: V6 likewise forbidden, V5 unaffected). Old TOML files without
    /// the field parse as None (serde default). Governed nonzero values stay
    /// UNSET pending the 4U sheet; None here is "unconfigured", never a
    /// governance choice.
    pub network_id: Option<u64>,
    /// PHASE 4CP-S: the P2P handshake protocol, selected EXPLICITLY by the
    /// operator. Deliberately INDEPENDENT of `network_id`, which stays a pure
    /// network identifier and is still checked during the handshake.
    ///
    /// `None` means "not configured": the node REFUSES to start rather than
    /// silently falling back to the unauthenticated legacy v5 handshake.
    ///
    /// Accepted TOML values: `p2p_protocol = "authenticated_v6"` (the
    /// authenticated testnet; requires a persistent node identity, loaded or
    /// created at boot) or `p2p_protocol = "legacy_v5"` (explicitly
    /// unauthenticated, preserved byte-for-byte). Pre-4CP-S TOML files that
    /// omit this field MUST be updated with an explicit choice.
    pub p2p_protocol: Option<P2PProtocolMode>,
    #[cfg(feature = "test-pipeline-trace")]
    #[serde(skip)]
    pub trace_label: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_type: "miner".into(),
            data_dir: default_data_dir(),
            p2p_port: 25565,
            rpc_port: 9933,
            rpc_bind: "127.0.0.1".into(),
            // Multi-seed defaults (Phase 1): several independent entry points so
            // the network does not depend on a single VPS. Operators can still
            // override via --bootnodes / TOML.
            bootnodes: vec![
                "103.102.135.123:25565".to_string(),
                "103.102.135.124:25565".to_string(),
                "103.102.135.125:25565".to_string(),
            ],
            dns_seeds: Vec::new(),
            miner_address: None,
            reset: false,
            repair_ledger: false,
            network_id: None,
            p2p_protocol: None,
            #[cfg(feature = "test-pipeline-trace")]
            trace_label: None,
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

    /// PHASE 4CP-S: resolve the EXPLICITLY configured P2P protocol mode.
    ///
    /// Fails closed on an unconfigured value: there is NO implicit legacy
    /// fallback. An unreadable value fails earlier (TOML parse error), so this
    /// only has to decide between an explicit choice and "not set".
    pub fn resolve_p2p_protocol(&self) -> Result<P2PProtocolMode, String> {
        self.p2p_protocol.ok_or_else(|| {
            "p2p_protocol is not set: refusing to start. Choose the P2P handshake \
             explicitly with `p2p_protocol = \"authenticated_v6\"` (authenticated \
             testnet; requires a node identity) or `p2p_protocol = \"legacy_v5\"` \
             (unauthenticated legacy)."
                .to_string()
        })
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

    /// 4CP-S / F3: the P2P mode is an EXPLICIT choice, never inferred from
    /// `network_id`, and an unset value fails closed instead of silently
    /// selecting the unauthenticated legacy handshake.
    #[test]
    fn test_p2p_protocol_requires_explicit_selection() {
        // Unset (default) => refuse.
        assert!(NodeConfig::default().resolve_p2p_protocol().is_err());
        // Independent of network_id: legacy with a nonzero network is legal,
        // v6 with the neutral network 0 is legal too — the two are decoupled.
        let mut legacy = NodeConfig::default();
        legacy.network_id = Some(7);
        legacy.p2p_protocol = Some(P2PProtocolMode::LegacyV5);
        assert_eq!(
            legacy.resolve_p2p_protocol().unwrap(),
            P2PProtocolMode::LegacyV5
        );
        let mut authenticated = NodeConfig::default();
        authenticated.network_id = None;
        authenticated.p2p_protocol = Some(P2PProtocolMode::AuthenticatedV6);
        assert_eq!(
            authenticated.resolve_p2p_protocol().unwrap(),
            P2PProtocolMode::AuthenticatedV6
        );
    }

    /// 4CP-S / F3: the TOML spelling of the choice, plus the fail-closed
    /// behavior for a config file that omits it entirely.
    #[test]
    fn test_p2p_protocol_toml_parsing() {
        let v6: NodeConfig =
            toml::from_str("node_type = \"miner\"\np2p_protocol = \"authenticated_v6\"\n")
                .expect("v6 TOML parses");
        assert_eq!(v6.p2p_protocol, Some(P2PProtocolMode::AuthenticatedV6));
        let v5: NodeConfig =
            toml::from_str("node_type = \"miner\"\np2p_protocol = \"legacy_v5\"\n")
                .expect("v5 TOML parses");
        assert_eq!(v5.p2p_protocol, Some(P2PProtocolMode::LegacyV5));
        let absent: NodeConfig =
            toml::from_str("node_type = \"miner\"\n").expect("minimal TOML parses");
        assert_eq!(absent.p2p_protocol, None);
        assert!(
            absent.resolve_p2p_protocol().is_err(),
            "an omitted p2p_protocol must fail closed, never silent legacy"
        );
        let bogus: Result<NodeConfig, _> =
            toml::from_str("node_type = \"miner\"\np2p_protocol = \"v7\"\n");
        assert!(bogus.is_err(), "an unknown mode must be a parse error");
    }
}
