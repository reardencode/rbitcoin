use crate::error::NodeError;
use bitcoin::hex::FromHex;
use bitcoin::ScriptBuf;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_primitives::Network;
use rbitcoin_store::HeadScale;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Default max concurrent inbound P2P sessions (same as net `DEFAULT_MAX_INBOUND`).
pub const DEFAULT_MAX_INBOUND: u32 = rbitcoin_net::DEFAULT_MAX_INBOUND as u32;

/// Core `-maxconnections=N` reserves this many slots for outbound full/block-relay
/// peers plus one feeler (`10 + 1`). Inbound capacity is `N - reserve`.
pub const CORE_MAXCONNECTIONS_OUTBOUND_RESERVE: u32 = 11;

/// Core total-slot flag → inbound session cap.
pub fn inbound_from_maxconnections(total: u32) -> u32 {
    total
        .saturating_sub(CORE_MAXCONNECTIONS_OUTBOUND_RESERVE)
        .max(1)
}

/// Process datadir (Class A store, cookie, debug.log, mempool).
///
/// Cold store is [`Self::cold`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatadirOpts {
    pub path: PathBuf,
    /// When set, Class A `inwit.body` / `inwit.idx/` live under `{cold}/store`.
    pub cold: Option<PathBuf>,
}

impl DatadirOpts {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl From<PathBuf> for DatadirOpts {
    fn from(path: PathBuf) -> Self {
        Self { path, cold: None }
    }
}

/// P2P / Electrum / Esplora listen and peer-count knobs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenOpts {
    pub p2p: Option<SocketAddr>,
    pub p2p_extra: Vec<SocketAddr>,
    pub electrum: Option<SocketAddr>,
    pub esplora: Option<SocketAddr>,
    pub connect: Vec<SocketAddr>,
    pub seednodes: Vec<String>,
    pub use_seeds: bool,
    pub max_outbound: u32,
    pub max_inbound: u32,
    pub max_inbound_explicit: bool,
    pub external_ips: Vec<std::net::IpAddr>,
    pub peer_timeout_secs: Option<u64>,
}

impl Default for ListenOpts {
    fn default() -> Self {
        Self {
            p2p: None,
            p2p_extra: Vec::new(),
            electrum: None,
            esplora: None,
            connect: Vec::new(),
            seednodes: Vec::new(),
            use_seeds: true,
            max_outbound: 16,
            max_inbound: DEFAULT_MAX_INBOUND,
            max_inbound_explicit: false,
            external_ips: Vec::new(),
            peer_timeout_secs: None,
        }
    }
}

/// Mempool size, persist, and policy overlays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolOpts {
    pub max_weight: u64,
    pub persist: bool,
    pub min_relay_fee_btc: Option<String>,
    pub expiry_hours: Option<u64>,
    pub limit_cluster_count: Option<u32>,
    pub limit_cluster_size_kvb: Option<u32>,
    pub permit_bare_multisig: bool,
    pub blocksonly: bool,
}

impl Default for MempoolOpts {
    fn default() -> Self {
        Self {
            max_weight: 300_000_000,
            persist: true,
            min_relay_fee_btc: None,
            expiry_hours: None,
            limit_cluster_count: None,
            limit_cluster_size_kvb: None,
            permit_bare_multisig: true,
            blocksonly: false,
        }
    }
}

/// JSON-RPC HTTP listen and auth.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RpcOpts {
    pub listen: Option<SocketAddr>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub work_queue: Option<usize>,
}

/// Node process configuration (CLI + optional conf file).
///
/// Operator-critical knobs live here. Advanced IO/perf tunables may still be
/// set via `RBITCOIN_*` env vars (documented as advanced); normal signet/mainnet
/// sync does not require any env export.
///
/// **Env input:** [`Self::absorb_inbound_env`] reads `RBITCOIN_P2P_MAX_INBOUND`
/// once when inbound was not set on CLI/conf. It never writes process env.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeConfig {
    pub datadir: DatadirOpts,
    pub listen: ListenOpts,
    pub mempool: MempoolOpts,
    pub rpc: RpcOpts,
    pub network: Network,
    /// Custom BIP325 challenge. `None` selects the default global Signet.
    pub signet_challenge: Option<ScriptBuf>,
    /// Custom Signet PoW target spacing in seconds.
    pub signet_block_time: Option<u64>,
    /// When true, open store and exit (CI / smoke).
    pub smoke: bool,
    /// Head geometry at store open. Production default is Mainnet. Tests and
    /// `--smoke` pass Tiny so they do not allocate multi‑GiB heads.
    pub head_scale: HeadScale,
    /// Cap how long `run_p2p` idles after sync (None = forever). Used by tests.
    pub max_run_secs: Option<u64>,
    /// Build Class B scripthash index (Electrum/Esplora history). Default **off**.
    pub shindex: bool,
    /// Persist / serve BIP-352 tweaks from `sp_tweaks.*`. Default **off**.
    pub sptweaks: bool,
    /// Electrum tweaks: omit P2TR outs with `value <=` this (sats). `0` serves
    /// all. Default [`rbitcoin_electrum::DEFAULT_TWEAKS_MIN_DUST`] (1000).
    pub sptweaks_dust: u64,
    /// Skip script/prevout checks for blocks at or below this height (0 = off).
    pub milestone_height: u32,
    /// Set when conf or CLI applied `milestone` / `assumevalid_height` (including 0).
    pub milestone_explicit: bool,
    /// When true, ask systemd (if available) to block automatic suspend/idle.
    pub inhibit_suspend: bool,
    /// Optional conf file path that was loaded (for diagnostics).
    pub conf_path: Option<PathBuf>,
    /// Log level from conf (`log_level=…`), if any. CLI `--log-level` overrides.
    pub conf_log_level: Option<String>,
    /// Optional JSONL API call log (`--api-log` / `api_log=`).
    pub api_log: Option<PathBuf>,
    /// Core `-asmap` path. `None` = try `{datadir}/ip_asn.dat` if present.
    pub asmap: Option<PathBuf>,
    /// Core `-uacomment` fragments (BIP14 parens in subversion).
    pub uacomments: Vec<String>,
    /// Core `-testactivationheight=name@height` (regtest).
    pub test_activation_heights: Vec<(String, u32)>,
    /// Core `-whitelist=` permission strings (stored; noban honor follows PeerHub).
    pub whitelist: Vec<String>,
    /// Core `-startupnotify` shell command (run once after start).
    pub startup_notify: Option<String>,
    /// Core `-alertnotify` shell command (`%s` = warning text).
    pub alert_notify: Option<String>,
    /// Core `-minimumchainwork` (32-byte BE work). `None` = no extra IBD floor.
    pub minimum_chain_work: Option<[u8; 32]>,
    /// Core `-mocktime` at start (`None` = wall clock).
    pub mock_time: Option<i64>,
    /// Core `-maxtipage` seconds (`None` = 24h default on ChainHub).
    pub max_tip_age_secs: Option<u64>,
    /// Core `-blockversion` GBT override (`None` = default).
    pub block_version: Option<i32>,
    /// Core `-blockmintxfee` as BTC/kvB text (`None` = default 1 sat/kvB).
    pub block_min_tx_fee_btc: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            datadir: DatadirOpts {
                path: Self::default_datadir(),
                cold: None,
            },
            listen: ListenOpts::default(),
            mempool: MempoolOpts::default(),
            rpc: RpcOpts::default(),
            network: Network::Mainnet,
            signet_challenge: None,
            signet_block_time: None,
            smoke: false,
            head_scale: HeadScale::Mainnet,
            max_run_secs: None,
            shindex: false,
            sptweaks: false,
            sptweaks_dust: rbitcoin_electrum::DEFAULT_TWEAKS_MIN_DUST,
            milestone_height: 0,
            milestone_explicit: false,
            inhibit_suspend: false,
            conf_path: None,
            conf_log_level: None,
            api_log: None,
            asmap: None,
            uacomments: Vec::new(),
            test_activation_heights: Vec::new(),
            whitelist: Vec::new(),
            startup_notify: None,
            alert_notify: None,
            minimum_chain_work: None,
            mock_time: None,
            max_tip_age_secs: None,
            block_version: None,
            block_min_tx_fee_btc: None,
        }
    }
}

impl NodeConfig {
    /// Cwd-relative `datadir` using the host path separator.
    ///
    /// `PathBuf::from("./datadir")` keeps a `/` in the OsString on Windows, so
    /// later `join` produces mixed `./datadir\store`. `.` + `join("datadir")`
    /// is `./datadir` on Unix and `.\datadir` on Windows.
    pub fn default_datadir() -> PathBuf {
        PathBuf::from(".").join("datadir")
    }

    /// `/rbitcoin:VERSION/` or `/rbitcoin:VERSION(comment; …)/`.
    pub fn subversion(&self) -> Result<String, crate::error::NodeError> {
        rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &self.uacomments)
            .map_err(crate::error::NodeError::Config)
    }

    pub fn with_datadir(mut self, datadir: impl Into<PathBuf>) -> Self {
        self.datadir.path = datadir.into();
        self
    }

    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub fn with_p2p_listen(mut self, addr: SocketAddr) -> Self {
        self.listen.p2p = Some(addr);
        self
    }

    /// Tiny heads for tests (64 header slots, 1 SH shard, 16-bit tx.head).
    pub fn with_tiny_heads(mut self) -> Self {
        self.head_scale = HeadScale::Tiny;
        self
    }

    pub fn store_path(&self) -> PathBuf {
        self.datadir.path().join("store")
    }

    /// Cold store directory (`{datadir-cold}/store`) when `--datadir-cold` is set.
    pub fn store_cold_path(&self) -> Option<PathBuf> {
        self.datadir.cold.as_ref().map(|p| p.join("store"))
    }

    pub fn store_layout(&self) -> rbitcoin_store::StoreLayout {
        let mut layout = match self.head_scale {
            HeadScale::Tiny => rbitcoin_store::StoreLayout::tiny(self.store_path()),
            HeadScale::Mainnet => rbitcoin_store::StoreLayout::single(self.store_path()),
        };
        if let Some(cold) = self.store_cold_path() {
            layout = layout.with_cold_dir(cold);
        }
        layout
    }

    /// Durable mempool directory (`{datadir}/mempool/`).
    pub fn mempool_path(&self) -> PathBuf {
        self.datadir.path().join("mempool")
    }

    pub fn milestone(&self) -> Milestone {
        if self.milestone_height == 0 {
            Milestone::NONE
        } else {
            Milestone {
                height: self.milestone_height,
            }
        }
    }

    /// Compose immutable consensus parameters from operator configuration.
    pub fn chain_params(&self) -> Result<ChainParams, NodeError> {
        let mut params = match self.signet_challenge.clone() {
            Some(challenge) => {
                ChainParams::custom_signet(challenge, self.signet_block_time.unwrap_or(10 * 60))
                    .map_err(|e| NodeError::Config(e.into()))?
            }
            None => ChainParams::for_network(self.network),
        };
        for (name, height) in &self.test_activation_heights {
            params
                .apply_test_activation_height(name, *height)
                .map_err(|e| {
                    NodeError::Config(format!("testactivationheight {name}@{height}: {e}"))
                })?;
        }
        Ok(params)
    }

    pub fn validate(&self) -> Result<(), NodeError> {
        if self.datadir.path().as_os_str().is_empty() {
            return Err(NodeError::Config("datadir must not be empty".into()));
        }
        if let Some(cold) = &self.datadir.cold {
            if cold.as_os_str().is_empty() {
                return Err(NodeError::Config("datadir-cold must not be empty".into()));
            }
            if cold == &self.datadir.path {
                return Err(NodeError::Config(
                    "datadir-cold must differ from datadir".into(),
                ));
            }
        }
        if self.listen.max_outbound == 0 {
            return Err(NodeError::Config("max_outbound must be >= 1".into()));
        }
        if self.listen.max_inbound == 0 {
            return Err(NodeError::Config("max_inbound must be >= 1".into()));
        }
        if (self.signet_challenge.is_some() || self.signet_block_time.is_some())
            && self.network != Network::Signet
        {
            return Err(NodeError::Config(
                "signetchallenge and signetblocktime require network=signet".into(),
            ));
        }
        if self.signet_block_time.is_some() && self.signet_challenge.is_none() {
            return Err(NodeError::Config(
                "signetblocktime requires signetchallenge".into(),
            ));
        }
        if self.signet_block_time == Some(0) {
            return Err(NodeError::Config(
                "signetblocktime must be greater than zero".into(),
            ));
        }
        if self.listen.electrum.is_some() && !self.shindex {
            return Err(NodeError::Config(
                "electrum_listen requires shindex=1 (--shindex); Electrum history needs Class B scripthash"
                    .into(),
            ));
        }
        if self.listen.esplora.is_some() && !self.shindex {
            return Err(NodeError::Config(
                "esplora_listen requires shindex=1 (--shindex); Esplora history needs Class B scripthash"
                    .into(),
            ));
        }
        if self.rpc.listen.is_some() && (self.rpc.user.is_some() ^ self.rpc.password.is_some()) {
            return Err(NodeError::Config(
                "rpcuser and rpcpassword must both be set (or both unset for cookie auth)".into(),
            ));
        }
        Ok(())
    }

    /// Path for Core-style RPC cookie (`{datadir}/.cookie`).
    pub fn rpc_cookie_path(&self) -> PathBuf {
        self.datadir.path().join(".cookie")
    }

    /// Create `{datadir}` and standard subdirs (`store`, `mempool`) if missing.
    pub fn ensure_datadir(&self) -> Result<(), NodeError> {
        self.validate()?;
        let root = self.datadir.path();
        let created_root = !root.exists();
        std::fs::create_dir_all(root).map_err(|source| NodeError::Datadir {
            path: self.datadir.path.clone(),
            source,
        })?;
        if root.exists() && !root.is_dir() {
            return Err(NodeError::Config(format!(
                "datadir is not a directory: {}",
                root.display()
            )));
        }
        for sub in ["store", "mempool"] {
            let p = root.join(sub);
            std::fs::create_dir_all(&p).map_err(|source| NodeError::Datadir { path: p, source })?;
        }
        if let Some(cold) = &self.datadir.cold {
            if cold.exists() && !cold.is_dir() {
                return Err(NodeError::Config(format!(
                    "datadir-cold is not a directory: {}",
                    cold.display()
                )));
            }
            let created_cold = !cold.exists();
            std::fs::create_dir_all(cold).map_err(|source| NodeError::Datadir {
                path: cold.clone(),
                source,
            })?;
            let store = cold.join("store");
            std::fs::create_dir_all(&store).map_err(|source| NodeError::Datadir {
                path: store,
                source,
            })?;
            if created_cold {
                rbitcoin_log::info!("node: created datadir-cold {}", cold.display());
            }
        }
        if created_root {
            rbitcoin_log::info!("node: created datadir {}", self.datadir.path().display());
        }
        Ok(())
    }

    /// If inbound was not explicit on CLI/conf, honor `RBITCOIN_P2P_MAX_INBOUND`.
    ///
    /// Input only — does not publish process env.
    pub fn absorb_inbound_env(&mut self) {
        if self.listen.max_inbound_explicit {
            return;
        }
        if let Some(n) = std::env::var("RBITCOIN_P2P_MAX_INBOUND")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n: &u32| n > 0)
        {
            self.listen.max_inbound = n;
        }
    }

    /// Load a simple `key=value` conf (Core-style lines; `#` comments).
    ///
    /// Supported keys: `datadir`, `datadir-cold` / `datadir_cold`, `network` / `chain`, `listen`, `connect` (repeatable),
    /// `milestone` / `assumevalid_height`, `maxoutbound` / `max_outbound`,
    /// `maxinbound` / `max_inbound`, `maxconnections` (Core total → inbound N-11),
    /// `mempool_size_mb` / `maxmempool`,
    /// `log_level`, `api_log`, `asmap`, `electrum_listen`, `esplora_listen`,
    /// `shindex`, `sptweaks`, `sptweaks_dust`, `rpc_listen`, `rpcuser`, `rpcpassword`,
    /// `noseeds` / `no_seeds`, `signetchallenge`, and `signetblocktime`.
    pub fn merge_conf_file(&mut self, path: &Path) -> Result<(), NodeError> {
        let text = std::fs::read_to_string(path).map_err(|source| {
            NodeError::Config(format!("read conf {}: {source}", path.display()))
        })?;
        self.conf_path = Some(path.to_path_buf());
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let (key, val) = match line.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => {
                    // Boolean Core-style flags: `noseeds=1` preferred; bare `regtest=1`.
                    if line.eq_ignore_ascii_case("regtest") {
                        self.network = Network::Regtest;
                        continue;
                    }
                    if line.eq_ignore_ascii_case("signet") {
                        self.network = Network::Signet;
                        continue;
                    }
                    if line.eq_ignore_ascii_case("testnet") {
                        self.network = Network::Testnet;
                        continue;
                    }
                    return Err(NodeError::Config(format!(
                        "conf {}:{}: expected key=value (got `{line}`)",
                        path.display(),
                        lineno + 1
                    )));
                }
            };
            match self.apply_kv(key, val)? {
                ConfApply::Applied => {}
                ConfApply::Unknown(other) => {
                    rbitcoin_log::warn!(
                        "node: conf {}:{}: unknown key `{other}` ignored",
                        path.display(),
                        lineno + 1
                    );
                }
            }
        }
        Ok(())
    }

    /// Apply one conf / CLI-equivalent `key=value`. Unknown keys are not errors.
    pub fn apply_kv(&mut self, key: &str, val: &str) -> Result<ConfApply, NodeError> {
        let key_l = key.to_ascii_lowercase();
        match key_l.as_str() {
            "datadir" => self.datadir.path = PathBuf::from(val),
            "datadir-cold" | "datadir_cold" | "datadircold" => {
                if val.is_empty() {
                    return Err(NodeError::Config(
                        "conf datadir-cold requires a path".into(),
                    ));
                }
                self.datadir.cold = Some(PathBuf::from(val));
            }
            "network" | "chain" => {
                self.network = Network::parse(val)
                    .map_err(|e| NodeError::Config(format!("conf network: {e}")))?;
            }
            "signetchallenge" | "signet_challenge" => {
                self.signet_challenge = Some(
                    parse_signet_challenge(val)
                        .map_err(|e| NodeError::Config(format!("conf signetchallenge: {e}")))?,
                );
            }
            "signetblocktime" | "signet_block_time" => {
                self.signet_block_time = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf signetblocktime: {e}")))?,
                );
            }
            "listen" => {
                let addr: SocketAddr = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf listen: {e}")))?;
                if self.listen.p2p.is_none() {
                    self.listen.p2p = Some(addr);
                } else {
                    self.listen.p2p_extra.push(addr);
                }
            }
            "connect" => {
                self.listen.connect.push(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf connect: {e}")))?,
                );
            }
            "seednode" => {
                if !val.is_empty() {
                    self.listen.seednodes.push(val.to_string());
                }
            }
            "electrum_listen" | "electrumlisten" => {
                self.listen.electrum = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf electrum_listen: {e}")))?,
                );
            }
            "esplora_listen" | "esploralisten" => {
                self.listen.esplora = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf esplora_listen: {e}")))?,
                );
            }
            "shindex" => {
                self.shindex = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf shindex: {e}")))?;
            }
            "sptweaks" => {
                self.sptweaks = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf sptweaks: {e}")))?;
            }
            "sptweaks_dust" | "sptweaksdust" => {
                self.sptweaks_dust = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf sptweaks_dust: {e}")))?;
            }
            "rpc_listen" | "rpclisten" => {
                self.rpc.listen = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf rpc_listen: {e}")))?,
                );
            }
            "rpcuser" | "rpc_user" => self.rpc.user = Some(val.to_string()),
            "rpcpassword" | "rpc_password" => self.rpc.password = Some(val.to_string()),
            "uacomment" => self.uacomments.push(val.to_string()),
            "testactivationheight" | "test_activation_height" => {
                let (name, height) = ChainParams::parse_test_activation_height(val)
                    .map_err(|e| NodeError::Config(format!("conf testactivationheight: {e}")))?;
                self.test_activation_heights
                    .push((name.to_string(), height));
            }
            "persistmempool" | "persist_mempool" => {
                self.mempool.persist = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf persistmempool: {e}")))?;
            }
            "whitelist" => {
                if !val.is_empty() {
                    self.whitelist.push(val.to_string());
                }
            }
            "blocksonly" | "blocks_only" => {
                self.mempool.blocksonly = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf blocksonly: {e}")))?;
            }
            "minrelaytxfee" | "min_relay_txfee" => {
                if val.is_empty() {
                    return Err(NodeError::Config(
                        "conf minrelaytxfee requires a value".into(),
                    ));
                }
                self.mempool.min_relay_fee_btc = Some(val.to_string());
            }
            "mempoolexpiry" | "mempool_expiry" => {
                let h: u64 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf mempoolexpiry: {e}")))?;
                self.mempool.expiry_hours = Some(h.max(1));
            }
            "startupnotify" | "startup_notify" => {
                if !val.is_empty() {
                    self.startup_notify = Some(val.to_string());
                }
            }
            "permitbaremultisig" | "permit_bare_multisig" => {
                self.mempool.permit_bare_multisig = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf permitbaremultisig: {e}")))?;
            }
            "limitclustercount" | "limit_cluster_count" => {
                self.mempool.limit_cluster_count = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf limitclustercount: {e}")))?,
                );
            }
            "limitclustersize" | "limit_cluster_size" => {
                self.mempool.limit_cluster_size_kvb = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf limitclustersize: {e}")))?,
                );
            }
            "externalip" | "external_ip" => {
                if val.is_empty() {
                    return Err(NodeError::Config(
                        "conf externalip requires an address".into(),
                    ));
                }
                let ip: std::net::IpAddr = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf externalip: {e}")))?;
                self.listen.external_ips.push(ip);
            }
            "peertimeout" | "peer_timeout" => {
                let n: u64 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf peertimeout: {e}")))?;
                if n == 0 {
                    return Err(NodeError::Config(
                        "peertimeout must be a positive integer.".into(),
                    ));
                }
                self.listen.peer_timeout_secs = Some(n);
            }
            "minimumchainwork" | "minimum_chain_work" => {
                self.minimum_chain_work =
                    Some(parse_minimum_chain_work(val).map_err(NodeError::Config)?);
            }
            "milestone" | "assumevalid_height" | "assumevalidheight" => {
                self.milestone_height = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf milestone: {e}")))?;
                self.milestone_explicit = true;
            }
            "maxoutbound" | "max_outbound" => {
                let n: u32 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf maxoutbound: {e}")))?;
                if n == 0 {
                    return Err(NodeError::Config("conf maxoutbound must be >= 1".into()));
                }
                self.listen.max_outbound = n;
            }
            "maxinbound" | "max_inbound" => {
                let n: u32 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf maxinbound: {e}")))?;
                if n == 0 {
                    return Err(NodeError::Config("conf maxinbound must be >= 1".into()));
                }
                self.listen.max_inbound = n;
                self.listen.max_inbound_explicit = true;
            }
            "maxconnections" => {
                let total: u32 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf maxconnections: {e}")))?;
                if total == 0 {
                    return Err(NodeError::Config("conf maxconnections must be >= 1".into()));
                }
                self.listen.max_inbound = inbound_from_maxconnections(total);
                self.listen.max_inbound_explicit = true;
            }
            "mempool_size_mb" | "maxmempool" => {
                let mb: u64 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf mempool_size_mb: {e}")))?;
                if mb == 0 {
                    return Err(NodeError::Config(
                        "conf mempool_size_mb must be >= 1".into(),
                    ));
                }
                self.mempool.max_weight = mb.saturating_mul(1_000_000);
            }
            "log_level" => {
                if val.is_empty() {
                    return Err(NodeError::Config("conf log_level requires a value".into()));
                }
                self.conf_log_level = Some(val.to_string());
            }
            "api_log" | "apilog" => {
                if val.is_empty() {
                    return Err(NodeError::Config("conf api_log requires a path".into()));
                }
                self.api_log = Some(PathBuf::from(val));
            }
            "asmap" => {
                if val.is_empty() {
                    return Err(NodeError::Config("conf asmap requires a path".into()));
                }
                self.asmap = Some(PathBuf::from(val));
            }
            "rpcworkqueue" | "rpc_work_queue" => {
                let n: usize = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf rpcworkqueue: {e}")))?;
                if n == 0 {
                    return Err(NodeError::Config("conf rpcworkqueue must be >= 1".into()));
                }
                self.rpc.work_queue = Some(n);
            }
            "max_run_secs" | "maxrunsecs" => {
                self.max_run_secs = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf max_run_secs: {e}")))?,
                );
            }
            "inhibit_suspend" | "inhibitsuspend" => {
                self.inhibit_suspend = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf inhibit_suspend: {e}")))?;
            }
            "mocktime" | "mock_time" => {
                let n: i64 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf mocktime: {e}")))?;
                if n < 0 {
                    return Err(NodeError::Config("conf mocktime must be >= 0".into()));
                }
                self.mock_time = Some(n);
            }
            "maxtipage" | "max_tip_age" => {
                let n: i64 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf maxtipage: {e}")))?;
                if n < 0 {
                    return Err(NodeError::Config("conf maxtipage must be >= 0".into()));
                }
                self.max_tip_age_secs = Some(n as u64);
            }
            "blockversion" | "block_version" => {
                self.block_version = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf blockversion: {e}")))?,
                );
            }
            "blockmintxfee" | "block_min_tx_fee" => {
                if val.is_empty() {
                    return Err(NodeError::Config(
                        "conf blockmintxfee requires a value".into(),
                    ));
                }
                self.block_min_tx_fee_btc = Some(val.to_string());
            }
            "alertnotify" | "alert_notify" => {
                if !val.is_empty() {
                    self.alert_notify = Some(val.to_string());
                }
            }
            "noseeds" | "no_seeds" => self.listen.use_seeds = !is_conf_true(val),
            "regtest" if is_conf_true(val) => self.network = Network::Regtest,
            "signet" if is_conf_true(val) => self.network = Network::Signet,
            "testnet" if is_conf_true(val) => self.network = Network::Testnet,
            other => return Ok(ConfApply::Unknown(other.to_string())),
        }
        Ok(ConfApply::Applied)
    }
}

/// Result of [`NodeConfig::apply_kv`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfApply {
    Applied,
    Unknown(String),
}

pub(crate) fn parse_signet_challenge(value: &str) -> Result<ScriptBuf, String> {
    Vec::<u8>::from_hex(value)
        .map(ScriptBuf::from_bytes)
        .map_err(|e| format!("must be hexadecimal: {e}"))
}

fn is_conf_true(val: &str) -> bool {
    matches!(
        val.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | ""
    )
}

/// Parse `1`/`true`/`yes`/`on` → true; `0`/`false`/`no`/`off` → false.
fn parse_conf_bool(val: &str) -> Result<bool, String> {
    let v = val.to_ascii_lowercase();
    match v.as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("expected 0|1|true|false (got `{val}`)")),
    }
}

/// Core `-minimumchainwork=<hex>` (optional `0x`, at most 64 hex digits).
pub fn parse_minimum_chain_work(spec: &str) -> Result<[u8; 32], String> {
    let hex = spec
        .strip_prefix("0x")
        .or_else(|| spec.strip_prefix("0X"))
        .unwrap_or(spec);
    if hex.len() > 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "Invalid minimum work specified ({spec}), must be up to 64 hex digits"
        ));
    }
    let mut padded = String::from("0").repeat(64 - hex.len());
    padded.push_str(hex);
    let raw = rbitcoin_primitives::hex_decode(&padded).map_err(|_| {
        format!("Invalid minimum work specified ({spec}), must be up to 64 hex digits")
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

impl NodeConfig {
    /// True when tip work meets `-minimumchainwork` (or the flag is unset).
    pub fn meets_minimum_chain_work(&self, tip_work_be: [u8; 32]) -> bool {
        match self.minimum_chain_work {
            None => true,
            Some(min) => tip_work_be >= min,
        }
    }
}

/// Serialize tests that mutate process `RBITCOIN_*` env (CLI + config unit tests).
#[cfg(test)]
pub(crate) static OPERATOR_ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rbitcoin-node-cfg-{n}"))
    }

    #[test]
    fn apply_kv_is_the_conf_setter_and_unknown_is_not_error() {
        let mut c = NodeConfig::default();
        assert_eq!(
            c.apply_kv("network", "regtest").unwrap(),
            ConfApply::Applied
        );
        assert_eq!(c.network, Network::Regtest);
        assert_eq!(
            c.apply_kv("datadir", "/tmp/rb-apply-kv").unwrap(),
            ConfApply::Applied
        );
        assert_eq!(c.datadir.path(), Path::new("/tmp/rb-apply-kv"));
        match c.apply_kv("not-a-real-key", "1").unwrap() {
            ConfApply::Unknown(k) => assert_eq!(k, "not-a-real-key"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn default_datadir_is_native_cwd_relative() {
        let p = NodeConfig::default_datadir();
        assert_eq!(p, PathBuf::from(".").join("datadir"));
        assert_eq!(NodeConfig::default().datadir.path(), p.as_path());
        let store = p.join("store");
        #[cfg(windows)]
        {
            let s = store.to_string_lossy();
            assert!(
                !s.contains('/'),
                "default datadir must use Windows separators, got {s}"
            );
            assert_eq!(p.to_str(), Some(r".\datadir"));
        }
        #[cfg(not(windows))]
        {
            assert_eq!(p.to_str(), Some("./datadir"));
            assert_eq!(store.to_str(), Some("./datadir/store"));
        }
    }

    #[test]
    fn store_layout_default_is_mainnet_tiny_builder_is_tiny() {
        let mainnet = NodeConfig::default();
        assert_eq!(mainnet.head_scale, HeadScale::Mainnet);
        assert_eq!(mainnet.store_layout().head_scale, HeadScale::Mainnet);
        assert_eq!(mainnet.store_layout().header_slots(), 1 << 22);
        assert_eq!(mainnet.store_layout().sh_shard_count(), 64);
        // Do not create those files in the default suite.

        let tiny = NodeConfig::default().with_tiny_heads();
        assert_eq!(tiny.head_scale, HeadScale::Tiny);
        assert_eq!(tiny.store_layout().head_scale, HeadScale::Tiny);
        assert_eq!(tiny.store_layout().header_slots(), 64);
        assert_eq!(tiny.store_layout().sh_shard_count(), 1);

        let dir = tmp();
        let mut split = NodeConfig::default().with_datadir(&dir).with_tiny_heads();
        split.datadir.cold = Some(dir.join("cold"));
        assert_eq!(split.store_layout().head_scale, HeadScale::Tiny);
        assert_eq!(
            split.store_layout().cold_dir.as_deref(),
            Some(dir.join("cold").join("store").as_path())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn builders_paths_milestone_and_ensure() {
        let dir = tmp();
        let cfg = NodeConfig::default()
            .with_datadir(&dir)
            .with_network(Network::Regtest)
            .with_p2p_listen("127.0.0.1:0".parse().unwrap());
        assert_eq!(cfg.network, Network::Regtest);
        assert_eq!(cfg.store_path(), dir.join("store"));
        assert_eq!(cfg.store_cold_path(), None);
        assert_eq!(cfg.mempool_path(), dir.join("mempool"));
        assert_eq!(cfg.listen.max_inbound, DEFAULT_MAX_INBOUND);
        assert!(!cfg.listen.max_inbound_explicit);
        cfg.ensure_datadir().unwrap();
        assert!(dir.join("store").is_dir());
        assert!(dir.join("mempool").is_dir());
        cfg.ensure_datadir().unwrap();
        let cold = dir.join("cold");
        let mut split = NodeConfig::default().with_datadir(&dir);
        split.datadir.cold = Some(cold.clone());
        assert_eq!(
            split.store_cold_path().as_deref(),
            Some(cold.join("store").as_path())
        );
        split.ensure_datadir().unwrap();
        assert!(cold.join("store").is_dir());
        let mut same = NodeConfig::default().with_datadir(&dir);
        same.datadir.cold = Some(dir.clone());
        assert!(same.validate().unwrap_err().to_string().contains("differ"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn conf_file_maps_operator_knobs() {
        let dir = tmp();
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("rbitcoin.conf");
        std::fs::write(
            &conf,
            "# test conf\n\
             network=signet\n\
             maxinbound=40\n\
             maxoutbound=8\n\
             mempool_size_mb=50\n\
             milestone=100\n\
             log_level=debug\n\
             api_log=/tmp/rbitcoin-api.jsonl\n\
             asmap=/tmp/ip_asn.dat\n\
             connect=127.0.0.1:38333\n\
             datadir-cold=/mnt/hdd/rbtc-cold\n",
        )
        .unwrap();
        let mut cfg = NodeConfig::default().with_datadir(dir.join("data"));
        cfg.merge_conf_file(&conf).unwrap();
        assert_eq!(cfg.network, Network::Signet);
        assert_eq!(cfg.listen.max_inbound, 40);
        assert!(cfg.listen.max_inbound_explicit);
        assert_eq!(cfg.listen.max_outbound, 8);
        assert_eq!(cfg.mempool.max_weight, 50_000_000);
        assert_eq!(cfg.milestone_height, 100);
        assert_eq!(cfg.conf_log_level.as_deref(), Some("debug"));
        assert_eq!(
            cfg.api_log.as_deref(),
            Some(std::path::Path::new("/tmp/rbitcoin-api.jsonl"))
        );
        assert_eq!(
            cfg.asmap.as_deref(),
            Some(std::path::Path::new("/tmp/ip_asn.dat"))
        );
        assert_eq!(cfg.listen.connect.len(), 1);
        assert_eq!(
            cfg.datadir.cold.as_deref(),
            Some(std::path::Path::new("/mnt/hdd/rbtc-cold"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Env is an input when inbound was not explicit; never published back.
    #[test]
    fn absorb_inbound_env_reads_but_does_not_write() {
        let _g = OPERATOR_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev_in = std::env::var_os("RBITCOIN_P2P_MAX_INBOUND");
        std::env::set_var("RBITCOIN_P2P_MAX_INBOUND", "99");
        let mut cfg = NodeConfig::default();
        assert!(!cfg.listen.max_inbound_explicit);
        cfg.absorb_inbound_env();
        assert_eq!(cfg.listen.max_inbound, 99);
        assert_eq!(
            std::env::var("RBITCOIN_P2P_MAX_INBOUND").as_deref(),
            Ok("99"),
            "absorb must not rewrite process env"
        );
        let mut explicit = NodeConfig::default();
        explicit.listen.max_inbound = 12;
        explicit.listen.max_inbound_explicit = true;
        explicit.absorb_inbound_env();
        assert_eq!(
            explicit.listen.max_inbound, 12,
            "explicit CLI/conf wins over env"
        );
        match prev_in {
            Some(v) => std::env::set_var("RBITCOIN_P2P_MAX_INBOUND", v),
            None => std::env::remove_var("RBITCOIN_P2P_MAX_INBOUND"),
        }
    }

    #[test]
    fn operator_knob_defaults_and_fields() {
        let mut cfg = NodeConfig::default();
        cfg.listen.max_inbound = 42;
        cfg.listen.max_inbound_explicit = true;
        assert_eq!(cfg.listen.max_inbound, 42);
        assert_eq!(
            NodeConfig::default().listen.max_inbound,
            DEFAULT_MAX_INBOUND
        );
    }

    #[test]
    fn maxconnections_derives_inbound_like_core() {
        assert_eq!(CORE_MAXCONNECTIONS_OUTBOUND_RESERVE, 11);
        assert_eq!(inbound_from_maxconnections(32), 21);
        assert_eq!(inbound_from_maxconnections(125), 114);
        assert_eq!(inbound_from_maxconnections(11), 1);
        assert_eq!(inbound_from_maxconnections(1), 1);
        let dir = tmp();
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("mc.conf");
        std::fs::write(&conf, "maxconnections=32\n").unwrap();
        let mut cfg = NodeConfig::default().with_datadir(dir.join("d"));
        cfg.merge_conf_file(&conf).unwrap();
        assert_eq!(cfg.listen.max_inbound, 21);
        assert!(cfg.listen.max_inbound_explicit);
        let conf2 = dir.join("mi.conf");
        std::fs::write(&conf2, "maxinbound=40\n").unwrap();
        let mut cfg2 = NodeConfig::default().with_datadir(dir.join("d2"));
        cfg2.merge_conf_file(&conf2).unwrap();
        assert_eq!(
            cfg2.listen.max_inbound, 40,
            "maxinbound stays explicit inbound"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn custom_signet_conf_builds_params() {
        let dir = tmp();
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("custom-signet.conf");
        std::fs::write(
            &conf,
            "network=signet\n\
             signetchallenge=51\n\
             signetblocktime=60\n",
        )
        .unwrap();

        let mut cfg = NodeConfig::default();
        cfg.merge_conf_file(&conf).unwrap();
        cfg.validate().unwrap();
        let params = cfg.chain_params().unwrap();
        assert_eq!(params.btc.pow_target_spacing, 60);
        assert_eq!(params.signet_challenge.unwrap().as_bytes(), &[0x51]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn custom_signet_options_require_signet_and_challenge() {
        let challenge = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        let mainnet = NodeConfig {
            signet_challenge: Some(challenge),
            ..NodeConfig::default()
        };
        assert!(mainnet.validate().is_err());

        let missing_challenge = NodeConfig {
            network: Network::Signet,
            signet_block_time: Some(30),
            ..NodeConfig::default()
        };
        assert!(missing_challenge.validate().is_err());
    }

    #[test]
    fn ensure_datadir_rejects_file_path_after_parent_exists() {
        let dir = tmp();
        std::fs::create_dir_all(&dir).unwrap();
        let file_as_dir = dir.join("notadir");
        std::fs::write(&file_as_dir, b"x").unwrap();
        let cfg = NodeConfig::default().with_datadir(&file_as_dir);
        assert!(cfg.ensure_datadir().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_datadir_rejects_file_as_subdir() {
        let dir = tmp();
        let cfg = NodeConfig::default().with_datadir(&dir);
        cfg.ensure_datadir().unwrap();
        // Make store a file so recreate fails.
        let _ = std::fs::remove_dir_all(dir.join("store"));
        std::fs::write(dir.join("store"), b"x").unwrap();
        let err = cfg.ensure_datadir().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("store") || msg.contains("datadir") || msg.contains("File exists"),
            "{msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_zero_peer_caps_and_empty_datadir() {
        let mut cfg = NodeConfig::default();
        cfg.datadir.path = PathBuf::new();
        assert!(cfg.validate().is_err());
        let mut cfg = NodeConfig::default().with_datadir(tmp());
        cfg.listen.max_outbound = 0;
        assert!(cfg.validate().is_err());
        cfg.listen.max_outbound = 1;
        cfg.listen.max_inbound = 0;
        assert!(cfg.validate().is_err());
        cfg.listen.max_inbound = 1;
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.milestone(), Milestone::NONE);
        cfg.milestone_height = 10;
        assert_eq!(cfg.milestone().height, 10);
    }

    #[test]
    fn conf_bare_network_flags_and_bad_line() {
        let dir = tmp();
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("flags.conf");
        std::fs::write(
            &conf,
            "regtest\n\
             # comment\n\
             ; also\n\
             \n\
             noseeds=1\n",
        )
        .unwrap();
        let mut cfg = NodeConfig::default().with_datadir(dir.join("d"));
        cfg.merge_conf_file(&conf).unwrap();
        assert_eq!(cfg.network, Network::Regtest);
        assert!(!cfg.listen.use_seeds);

        let conf2 = dir.join("signet.conf");
        std::fs::write(&conf2, "signet\n").unwrap();
        let mut cfg2 = NodeConfig::default().with_datadir(dir.join("d2"));
        cfg2.merge_conf_file(&conf2).unwrap();
        assert_eq!(cfg2.network, Network::Signet);

        let conf3 = dir.join("testnet.conf");
        std::fs::write(&conf3, "testnet\n").unwrap();
        let mut cfg3 = NodeConfig::default().with_datadir(dir.join("d3"));
        cfg3.merge_conf_file(&conf3).unwrap();
        assert_eq!(cfg3.network, Network::Testnet);

        let conf_bad = dir.join("bad.conf");
        std::fs::write(&conf_bad, "not_a_key_value\n").unwrap();
        let mut cfg_bad = NodeConfig::default().with_datadir(dir.join("db"));
        assert!(cfg_bad.merge_conf_file(&conf_bad).is_err());

        let missing = dir.join("nope.conf");
        assert!(cfg_bad.merge_conf_file(&missing).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn electrum_without_shindex_fails_validate() {
        let mut cfg = NodeConfig::default().with_datadir(tmp());
        cfg.listen.electrum = Some("127.0.0.1:50001".parse().unwrap());
        cfg.shindex = false;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("shindex"),
            "expected shindex requirement, got {err}"
        );
    }

    #[test]
    fn esplora_without_shindex_fails_validate() {
        let mut cfg = NodeConfig::default().with_datadir(tmp());
        cfg.listen.esplora = Some("127.0.0.1:3000".parse().unwrap());
        cfg.shindex = false;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("shindex"), "got {err}");
    }

    #[test]
    fn shindex_alone_validates() {
        let mut cfg = NodeConfig::default().with_datadir(tmp());
        cfg.shindex = true;
        cfg.validate().unwrap();
    }

    #[test]
    fn sptweaks_conf_parses() {
        let dir = tmp();
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("sp.conf");
        std::fs::write(&conf, "sptweaks=1\n").unwrap();
        let mut cfg = NodeConfig::default().with_datadir(dir.join("d"));
        cfg.merge_conf_file(&conf).unwrap();
        assert!(cfg.sptweaks);
        assert_eq!(
            cfg.sptweaks_dust,
            rbitcoin_electrum::DEFAULT_TWEAKS_MIN_DUST
        );
        cfg.validate().unwrap();
    }

    #[test]
    fn sptweaks_dust_conf_parses_and_zero_serves_all() {
        let dir = tmp();
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("dust.conf");
        std::fs::write(&conf, "sptweaks_dust=546\n").unwrap();
        let mut cfg = NodeConfig::default().with_datadir(dir.join("d"));
        cfg.merge_conf_file(&conf).unwrap();
        assert_eq!(cfg.sptweaks_dust, 546);
        let conf0 = dir.join("dust0.conf");
        std::fs::write(&conf0, "sptweaks_dust=0\n").unwrap();
        let mut cfg0 = NodeConfig::default().with_datadir(dir.join("d0"));
        cfg0.merge_conf_file(&conf0).unwrap();
        assert_eq!(cfg0.sptweaks_dust, 0);
        let bad = dir.join("dust-bad.conf");
        std::fs::write(&bad, "sptweaks_dust=nope\n").unwrap();
        let mut cfg_bad = NodeConfig::default().with_datadir(dir.join("db"));
        let err = cfg_bad.merge_conf_file(&bad).unwrap_err().to_string();
        assert!(err.contains("sptweaks_dust"), "{err}");
    }

    #[test]
    fn electrum_with_shindex_validates() {
        let mut cfg = NodeConfig::default().with_datadir(tmp());
        cfg.shindex = true;
        cfg.listen.electrum = Some("127.0.0.1:50001".parse().unwrap());
        cfg.validate().unwrap();
    }

    #[test]
    fn conf_keys_parse_and_error_paths() {
        let dir = tmp();
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("full.conf");
        std::fs::write(
            &conf,
            "listen=127.0.0.1:18444\n\
             connect=127.0.0.1:18445\n\
             shindex=1\n\
             electrum_listen=127.0.0.1:50001\n\
             esplora_listen=127.0.0.1:3000\n\
             rpc_listen=127.0.0.1:8332\n\
             milestone=100\n\
             maxoutbound=8\n\
             maxinbound=32\n\
             mempool_size_mb=50\n\
             log_level=info\n\
             noseeds=0\n\
             unknown_key=1\n\
             network=regtest\n",
        )
        .unwrap();
        let mut cfg = NodeConfig::default().with_datadir(dir.join("d"));
        cfg.merge_conf_file(&conf).unwrap();
        assert_eq!(cfg.network, Network::Regtest);
        assert!(cfg.listen.p2p.is_some());
        assert_eq!(cfg.listen.connect.len(), 1);
        assert!(cfg.shindex);
        assert!(!cfg.sptweaks);
        assert!(cfg.listen.electrum.is_some());
        assert!(cfg.listen.esplora.is_some());
        assert!(cfg.rpc.listen.is_some());
        assert_eq!(cfg.milestone_height, 100);
        assert_eq!(cfg.listen.max_outbound, 8);
        assert_eq!(cfg.listen.max_inbound, 32);
        assert!(cfg.listen.max_inbound_explicit);
        assert_eq!(cfg.mempool.max_weight, 50_000_000);
        assert_eq!(cfg.conf_log_level.as_deref(), Some("info"));
        assert!(cfg.listen.use_seeds); // noseeds=0 → seeds on

        // Error paths: bad listen / electrum / mempool 0 / empty log_level.
        for (body, needle) in [
            ("listen=not-an-addr\n", "listen"),
            ("electrum_listen=bad\n", "electrum"),
            ("esplora_listen=bad\n", "esplora"),
            ("mempool_size_mb=0\n", "mempool"),
            ("log_level=\n", "log_level"),
            ("network=notanet\n", "network"),
            ("milestone=x\n", "milestone"),
        ] {
            let p = dir.join(format!("bad-{needle}.conf"));
            std::fs::write(&p, body).unwrap();
            let mut c = NodeConfig::default().with_datadir(dir.join("dx"));
            let err = c.merge_conf_file(&p).unwrap_err();
            let msg = format!("{err}");
            assert!(
                msg.to_ascii_lowercase().contains(needle)
                    || msg.contains("conf")
                    || msg.contains("parse"),
                "body={body:?} msg={msg}"
            );
        }

        // ensure_datadir rejects a file path as datadir.
        let file_dd = dir.join("not-a-dir");
        std::fs::write(&file_dd, b"x").unwrap();
        let cfg_f = NodeConfig::default().with_datadir(&file_dd);
        assert!(cfg_f.ensure_datadir().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn testactivationheight_csv_overlay_on_chain_params() {
        let mut cfg = NodeConfig::default();
        cfg.network = Network::Regtest;
        cfg.test_activation_heights.push(("csv".into(), 102));
        let p = cfg.chain_params().unwrap();
        assert_eq!(p.csv_height(), 102);
        assert!(!p.csv_active_at(101));
        assert!(p.csv_active_at(102));
        // Libre defaults when the flag is absent.
        let plain = NodeConfig::default();
        assert!(plain.mempool.persist);
        assert!(!plain.mempool.blocksonly);
        assert!(plain.mempool.permit_bare_multisig);
        assert!(plain.test_activation_heights.is_empty());
        assert_eq!(
            NodeConfig {
                network: Network::Regtest,
                ..NodeConfig::default()
            }
            .chain_params()
            .unwrap()
            .csv_height(),
            1
        );
    }

    #[test]
    fn minimum_chain_work_hex_and_floor() {
        let w = parse_minimum_chain_work("0x65").unwrap();
        assert_eq!(w[31], 0x65);
        assert!(parse_minimum_chain_work("test").is_err());
        assert!(parse_minimum_chain_work(
            "01234567890123456789012345678901234567890123456789012345678901234"
        )
        .is_err());
        let mut cfg = NodeConfig::default();
        assert!(cfg.meets_minimum_chain_work([0; 32]));
        cfg.minimum_chain_work = Some(w);
        assert!(!cfg.meets_minimum_chain_work([0; 32]));
        let mut above = [0u8; 32];
        above[31] = 0x66;
        assert!(cfg.meets_minimum_chain_work(above));
    }
}
