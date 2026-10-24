use crate::error::NodeError;
use bitcoin::hex::FromHex;
use bitcoin::ScriptBuf;
use rbitcoin_consensus::{default_milestone_anchor, ChainParams, Milestone};
use rbitcoin_esplora::EsploraListen;
use rbitcoin_primitives::{
    Network, DEFAULT_ELECTRUM_PORT, DEFAULT_ESPLORA_PORT, DEFAULT_HEALTH_PORT,
};

use rbitcoin_store::HeadScale;
use std::ffi::{OsStr, OsString};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

/// Default max concurrent inbound P2P sessions (same as net `DEFAULT_MAX_INBOUND`).
pub const DEFAULT_MAX_INBOUND: u32 = rbitcoin_net::DEFAULT_MAX_INBOUND as u32;

/// P2P bind: omitted flag (loopback default), `--listen=0` / `--no-listen`, or an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum P2pListen {
    #[default]
    Auto,
    Off,
    Socket(SocketAddr),
}

/// Parse Core BTC/kvB (`0.00000001`) to sat/kvB. Negatives and junk fail.
pub fn parse_btc_to_sat(s: &str) -> Result<u64, &'static str> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty");
    }
    if s.starts_with('-') {
        return Err("must be non-negative");
    }
    let (whole_s, frac_s) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole_s.is_empty() && frac_s.is_empty() {
        return Err("invalid");
    }
    let whole: u64 = if whole_s.is_empty() {
        0
    } else {
        whole_s.parse().map_err(|_| "invalid")?
    };
    let mut frac = frac_s.to_string();
    if frac.len() > 8 {
        frac.truncate(8);
    }
    while frac.len() < 8 {
        frac.push('0');
    }
    let frac_n: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse().map_err(|_| "invalid")?
    };
    Ok(whole.saturating_mul(100_000_000).saturating_add(frac_n))
}

/// Process datadir (Class A store, rpc.token / rpc.sock, debug.log, mempool).
///
/// Cold store is [`Self::cold`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatadirOpts {
    pub path: PathBuf,
    /// When set, cold witness artifacts (`seqsigwit.*`, `seqsigwit.window/*`) live under `{cold}/store`.
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
    pub p2p: P2pListen,
    pub p2p_extra: Vec<SocketAddr>,
    pub electrum: Option<SocketAddr>,
    pub esplora: Option<EsploraListen>,
    /// `--health-listen`: `/healthz` from the start of `run_p2p`.
    pub health: Option<SocketAddr>,
    pub connect: Vec<rbitcoin_net::NetAddr>,
    /// `--connect` names that are not a `NetAddr` (clearnet DNS, Warnet tanks).
    pub connect_dns: Vec<String>,
    pub seednodes: Vec<String>,
    pub use_seeds: bool,
    pub max_outbound: u32,
    pub max_inbound: u32,
    pub max_inbound_explicit: bool,
    pub external_ips: Vec<std::net::IpAddr>,
    /// v3 `.onion` hosts from `--external-ip`. Advertised, not a reachability bit.
    pub external_onions: Vec<String>,
    pub peer_timeout_secs: Option<u64>,
    /// SOCKS5 for all P2P outbound (`--proxy`).
    pub proxy: Option<SocketAddr>,
    /// SOCKS5 for onion destinations (`--onion`); clearnet stays `--proxy` or direct.
    pub onion: Option<SocketAddr>,
    /// Fresh SOCKS USERPASS per peer (Core `-proxyrandomize`; default on).
    pub proxy_randomize: bool,
    /// Core `-discover` (default on). Off: no self-announce / localaddresses.
    pub discover: bool,
    /// Empty = all networks. Repeatable `--only-net`.
    pub only_net: Vec<rbitcoin_net::OnlyNet>,
    /// SAM v3 TCP port (`--i2p-sam`).
    pub i2p_sam: Option<SocketAddr>,
    /// Persistent SAM destination + STREAM FORWARD to the P2P bind (`--i2p-accept-incoming`).
    pub i2p_accept_incoming: bool,
    /// Loopback P2P accept + Tor `ADD_ONION` (`--listen-onion`).
    pub listen_onion: bool,
    /// `--listen` or `--no-listen` was set. Default auto-listen is not explicit.
    pub p2p_explicit: bool,
    /// Kernel CJDNS overlay (`fc00::/8`) is routable (`--cjdns-reachable`).
    pub cjdns_reachable: bool,
}

impl Default for ListenOpts {
    fn default() -> Self {
        Self {
            p2p: P2pListen::Auto,
            p2p_extra: Vec::new(),
            electrum: None,
            esplora: None,
            health: None,
            connect: Vec::new(),
            connect_dns: Vec::new(),
            seednodes: Vec::new(),
            use_seeds: true,
            max_outbound: 16,
            max_inbound: DEFAULT_MAX_INBOUND,
            max_inbound_explicit: false,
            external_ips: Vec::new(),
            external_onions: Vec::new(),
            peer_timeout_secs: None,
            proxy: None,
            onion: None,
            proxy_randomize: true,
            discover: true,
            only_net: Vec::new(),
            i2p_sam: None,
            i2p_accept_incoming: false,
            listen_onion: false,
            p2p_explicit: false,
            cjdns_reachable: false,
        }
    }
}

impl ListenOpts {
    pub fn has_pinned_connect(&self) -> bool {
        !self.connect.is_empty() || !self.connect_dns.is_empty()
    }

    pub fn dialer(&self) -> rbitcoin_net::Dialer {
        rbitcoin_net::Dialer::with_proxies(self.proxy, self.onion, self.proxy_randomize)
    }

    pub fn isolated_dialer(&self) -> rbitcoin_net::Dialer {
        rbitcoin_net::Dialer::with_proxies(self.proxy, self.onion, true)
    }

    pub fn p2p_bind_addr(&self, network: Network) -> Option<SocketAddr> {
        match self.p2p {
            P2pListen::Off => None,
            P2pListen::Auto => Some(SocketAddr::from((
                [127, 0, 0, 1],
                network.default_p2p_port(),
            ))),
            P2pListen::Socket(a) => Some(a),
        }
    }

    /// Clearnet bind, or a loopback ephemeral port when `--listen-onion` is on
    /// with `--no-listen`.
    pub fn start_p2p_bind(&self, network: Network) -> Option<SocketAddr> {
        if let Some(a) = self.p2p_bind_addr(network) {
            return Some(a);
        }
        if self.listen_onion {
            return Some(SocketAddr::from(([127, 0, 0, 1], 0)));
        }
        None
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
    /// Core `-bytespersigop` (`None` = 20; `0` disables sigop-adjusted size).
    pub bytes_per_sigop: Option<u64>,
    /// Sigops reserved for coinbase/template overhead (`None` = 400).
    pub block_reserved_sigops: Option<u64>,
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
            bytes_per_sigop: None,
            block_reserved_sigops: None,
            blocksonly: false,
        }
    }
}

/// System tor control port (cookie or password AUTH).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TorControlOpts {
    pub control: Option<SocketAddr>,
    pub cookie: Option<PathBuf>,
    pub password: Option<String>,
}

impl std::fmt::Debug for TorControlOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorControlOpts")
            .field("control", &self.control)
            .field("cookie", &self.cookie)
            .field("password", &self.password.as_ref().map(|_| "****"))
            .finish()
    }
}

/// SV2 authority secret key; `Debug` never prints it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sv2AuthoritySecret(pub [u8; 32]);

impl std::fmt::Debug for Sv2AuthoritySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("****")
    }
}

/// JSON-RPC listen and auth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcOpts {
    /// TCP bind. Filled from `--rpc-listen` (optional ADDR uses network default port).
    pub listen: Option<SocketAddr>,
    /// `--rpc-listen` was set with no ADDR; resolve after `--network`.
    pub listen_default: bool,
    /// Unix JSON-RPC socket (`--rpc`, `--rpc-listen`, or `--rpc-socket`).
    pub socket: bool,
    /// `--rpc-socket`: bind here, mode 0660, instead of `{datadir}/rpc.sock` (0600).
    pub socket_path: Option<PathBuf>,
    /// Override `{datadir}/rpc.token`.
    pub token_file: Option<PathBuf>,
    /// Opt-in Core-format `username:password` cookie accepted as TCP HTTP Basic.
    pub cookie_file: Option<PathBuf>,
    /// Widest Unix mode `--rpc-cookie-perms` allows. Default owner (0600).
    /// `group` is at most 0640. `all` is at most 0644.
    pub cookie_perms: rbitcoin_rpc::RpcCookiePerms,
    pub work_queue: Option<usize>,
    /// Core REST on the RPC listener. Off unless `--rest` / `rest=`.
    pub rest: bool,
    /// `submitpackage` uses Core `IsChildWithParents`. Set only from
    /// [`NodeEnv::rpc_package_dialect`].
    pub package_dialect: bool,
    /// RPC tip waits drain the tip-accept lane. Set only from
    /// [`NodeEnv::rpc_wait_tip_idle`].
    pub wait_tip_idle: bool,
}

impl Default for RpcOpts {
    fn default() -> Self {
        Self {
            listen: None,
            listen_default: false,
            socket: false,
            socket_path: None,
            token_file: None,
            cookie_file: None,
            cookie_perms: rbitcoin_rpc::RpcCookiePerms::Owner,
            work_queue: Some(rbitcoin_rpc::DEFAULT_RPC_WORK_QUEUE),
            rest: false,
            package_dialect: false,
            wait_tip_idle: false,
        }
    }
}

/// `RBITCOIN_*` node process env, read once by the process shell
/// ([`crate::process_main`]) and passed to [`crate::cli_main`].
/// An unset or empty knob keeps its default. A set value that is not UTF-8 or
/// does not parse is an error. A flag takes `1` or `true` (on) and `0` or
/// `false` (off), `true`/`false` in any case.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeEnv {
    /// `RBITCOIN_P2P_MAX_INBOUND`.
    pub p2p_max_inbound: Option<u32>,
    /// `RBITCOIN_BLOCK_QUEUE_BYTES`, else `RBITCOIN_BLOCK_QUEUE_GB` in GiB.
    /// `0` is unlimited (`u64::MAX`).
    pub bq_assign_stop_bytes: Option<u64>,
    /// `RBITCOIN_TEST_DROP_STORE` is on: `--smoke` deletes the store before
    /// shutdown, so the shutdown error path runs.
    pub test_drop_store: bool,
    /// `RBITCOIN_SH_FORCE_REBUILD` is on: tip SH finalize wipes the head and
    /// recollects all of Class A, on every start while it stays set.
    pub sh_force_rebuild: bool,
    /// `RBITCOIN_RPC_PACKAGE_DIALECT` is on: `submitpackage` uses Core
    /// `IsChildWithParents`.
    pub rpc_package_dialect: bool,
    /// `RBITCOIN_RPC_WAIT_TIP_IDLE` is on: `getblockcount`, `getbestblockhash`,
    /// and `wait_height` wait until the tip-accept lane is empty.
    pub rpc_wait_tip_idle: bool,
}

impl NodeEnv {
    /// Snapshot the process env. Only a process shell calls this.
    /// `std::env::var_os` matches each name as the platform does, which is
    /// case-insensitive on Windows.
    pub fn from_env() -> Result<Self, NodeError> {
        Self::from_lookup(|key| std::env::var_os(key))
    }

    /// Read each knob through `get`, which returns the value set for a name.
    pub fn from_lookup(mut get: impl FnMut(&str) -> Option<OsString>) -> Result<Self, NodeError> {
        let mut var = |key: &'static str| (key, get(key));
        let bq_bytes = env_num::<u64>(var("RBITCOIN_BLOCK_QUEUE_BYTES"))?;
        let bq_gib = env_num::<u64>(var("RBITCOIN_BLOCK_QUEUE_GB"))?;
        Ok(Self {
            p2p_max_inbound: env_num(var("RBITCOIN_P2P_MAX_INBOUND"))?,
            bq_assign_stop_bytes: bq_bytes
                .or(bq_gib.map(|g| g.saturating_mul(1 << 30)))
                .map(|n| if n == 0 { u64::MAX } else { n }),
            test_drop_store: env_flag(var("RBITCOIN_TEST_DROP_STORE"))?,
            sh_force_rebuild: env_flag(var("RBITCOIN_SH_FORCE_REBUILD"))?,
            rpc_package_dialect: env_flag(var("RBITCOIN_RPC_PACKAGE_DIALECT"))?,
            rpc_wait_tip_idle: env_flag(var("RBITCOIN_RPC_WAIT_TIP_IDLE"))?,
        })
    }
}

/// The value of a set env knob, `None` when unset or empty.
fn env_value<'a>(key: &str, val: Option<&'a OsStr>) -> Result<Option<&'a str>, NodeError> {
    match val.map(|v| (v, v.to_str())) {
        None | Some((_, Some(""))) => Ok(None),
        Some((_, Some(v))) => Ok(Some(v)),
        Some((v, None)) => Err(NodeError::Config(format!("{key}={v:?}: not UTF-8"))),
    }
}

fn env_num<T>((key, val): (&str, Option<OsString>)) -> Result<Option<T>, NodeError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    env_value(key, val.as_deref())?
        .map(|v| T::from_str(v).map_err(|e| NodeError::Config(format!("{key}={v:?}: {e}"))))
        .transpose()
}

fn env_flag((key, val): (&str, Option<OsString>)) -> Result<bool, NodeError> {
    match env_value(key, val.as_deref())? {
        None => Ok(false),
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => Ok(true),
        Some(v) if v == "0" || v.eq_ignore_ascii_case("false") => Ok(false),
        Some(v) => Err(NodeError::Config(format!(
            "{key}={v:?}: expected 1, true, 0, or false"
        ))),
    }
}

/// Node process configuration (CLI + optional conf file).
///
/// Operator-critical knobs live here. Advanced IO/perf tunables may still be
/// set via `RBITCOIN_*` env vars (documented as advanced); normal signet/mainnet
/// sync does not require any env export.
///
/// **Env input:** [`Self::absorb_inbound_env`] applies [`NodeEnv`] when
/// inbound was not set on CLI/conf.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NodeConfig {
    pub datadir: DatadirOpts,
    pub listen: ListenOpts,
    pub mempool: MempoolOpts,
    pub rpc: RpcOpts,
    pub tor: TorControlOpts,
    pub network: Network,
    /// Custom BIP325 challenge. `None` selects the default global Signet.
    pub signet_challenge: Option<ScriptBuf>,
    /// Custom Signet PoW target spacing in seconds.
    pub signet_block_time: Option<u64>,
    /// When true, open store and exit (CI / smoke).
    pub smoke: bool,
    /// When true, print the store's hot digest and exit (`--hot-digest`).
    pub hot_digest: bool,
    /// `--assumehot-from DATADIR --assumehot HASH`: import that datadir's
    /// store into this empty one before starting, checked by digest.
    pub assumehot: Option<(PathBuf, [u8; 32])>,
    /// Head geometry at store open. Production default is Mainnet. Tests and
    /// `--smoke` pass Tiny so they do not allocate multi‑GiB heads.
    pub head_scale: HeadScale,
    /// Cap how long `run_p2p` idles after sync (None = forever). Used by tests.
    pub max_run_secs: Option<u64>,
    /// Build Class B scripthash index (Electrum/Esplora history). Default **off**.
    pub shindex: bool,
    /// Rebuild the scripthash index from Class A at tip entry. Set only from
    /// [`NodeEnv::sh_force_rebuild`].
    pub sh_force_rebuild: bool,
    /// Build BIP158 basic block filters. Default **off**. Independent of `shindex`.
    pub block_filter_index: bool,
    /// Drop Class A seqsigwit below a 288-height watermark (`NETWORK_LIMITED`).
    pub prune_seqsigwit: bool,
    /// Main datadir is rotating media (`--datadir-hdd`). Default off.
    pub datadir_hdd: bool,
    /// RAM cap for the prune witness window. `0` keeps nothing in RAM.
    pub prune_seqsigwit_ram_threshold_bytes: u64,
    /// IBD densify assign-stop in block-queue bytes. `u64::MAX` is unlimited.
    /// Set only from [`NodeEnv::bq_assign_stop_bytes`].
    pub bq_assign_stop_bytes: u64,
    /// Persist / serve BIP-352 tweaks from `sp_tweaks.*`. Default **off**.
    pub sptweaks: bool,
    /// Electrum tweaks: omit P2TR outs with `value <=` this (sats). `0` serves
    /// all. Default [`rbitcoin_electrum::DEFAULT_TWEAKS_MIN_DUST`] (1000).
    pub sptweaks_dust: u64,
    /// 0 = unlimited. Electrum + Esplora refuse SH joins above this create count.
    pub max_sh_creates: u32,
    /// 0 = off. Unpaged SH joins above this create count run one at a time
    /// across the node.
    pub heavy_sh_creates: u32,
    /// Max `blockchain.scripthash.subscribe` entries per Electrum connection
    /// (>= 1). Default [`rbitcoin_electrum::DEFAULT_MAX_SCRIPTHASH_SUBS`].
    pub electrum_max_subs: usize,
    /// Max Esplora requests in flight across the whole listener (>= 1).
    /// Default [`rbitcoin_electrum::DEFAULT_MAX_CONNECTIONS`].
    pub esplora_max_inflight: usize,
    /// Opt-in Esplora `GET /block-template` (GBT template JSON). Default off.
    pub esplora_block_template: bool,
    /// Prometheus `GET /metrics` on the health listener. Default off.
    pub metrics: bool,
    /// ADD_ONION for `--esplora-listen` when `--tor-control` is set. Default on.
    pub esplora_onion: bool,
    /// SV2 Template Provider bind (`--sv2-tp-listen`). Default off.
    pub sv2_tp_listen: Option<SocketAddr>,
    /// Authority secret key the TP signs its Noise certificates with.
    pub sv2_tp_authority_sec: Option<Sv2AuthoritySecret>,
    /// Validity of each per-connection Noise certificate. Default 3600 s.
    pub sv2_tp_cert_validity_secs: u64,
    /// How long a template on a replaced tip still answers. Default 10 s.
    /// Conf and CLI set whole seconds; tests may set a shorter duration.
    pub sv2_tp_stale_grace: Duration,
    /// Drops a session that handles no frame for this long after its first
    /// `CoinbaseOutputConstraints`. Default zero: no idle deadline.
    pub sv2_tp_idle_timeout: Duration,
    /// Fee gain over a session's last template that pushes a rebuild on the
    /// same tip. Default 1000 sat.
    pub sv2_tp_fee_delta: u64,
    /// Minimum time from a session's last push to a fee push. Default 5 s.
    /// Conf and CLI set whole seconds (at least 1); tests may set the floor.
    pub sv2_tp_template_interval: Duration,
    /// How long a changed SV2 coinbase budget waits. Default
    /// [`rbitcoin_sv2::CONSTRAINTS_COOLDOWN`]. Not a conf key; tests that wait
    /// on the next budget set [`rbitcoin_sv2::CONSTRAINTS_COOLDOWN_TEST`].
    pub sv2_tp_constraints_cooldown: Duration,
    /// Skip script/prevout checks for blocks at or below this height (0 = off).
    pub milestone_height: u32,
    /// Set when conf or CLI applied `milestone` (including 0).
    pub milestone_explicit: bool,
    /// When true, ask systemd (if available) to block automatic suspend/idle.
    pub inhibit_suspend: bool,
    /// Optional conf file path that was loaded (for diagnostics).
    pub conf_path: Option<PathBuf>,
    /// Log level from conf (`log_level=…`), if any. CLI `--log-level` overrides.
    pub conf_log_level: Option<String>,
    /// Optional JSONL API call log (`--api-log` / `api_log=`).
    pub api_log: Option<PathBuf>,
    /// `--asmap` path. `None` = try `{datadir}/ip_asn.dat` if present.
    pub asmap: Option<PathBuf>,
    /// `--ua-comment` fragments (BIP14 parens in subversion).
    pub uacomments: Vec<String>,
    /// `--test-activation-height=name@height` (regtest).
    pub test_activation_heights: Vec<(String, u32)>,
    /// `--regtest-pow-bits` compact bits fixed for every regtest block >= 1.
    pub regtest_pow_bits: Option<u32>,
    /// Do not evict/ban inbound (`--trusted`; Core functional `-whitelist=noban`).
    pub trusted: bool,
    /// Always announce inbound txs (`--always-relay`; Core `forcerelay`).
    pub always_relay: bool,
    /// Permit tx relay to inbound while `--blocks-only` (`--relay`; Core `relay`).
    pub relay: bool,
    /// Parsed `--net-permission` / `--net-permission-bind` (implicit bits in [`Self::finalized_net_perms`]).
    pub net_perms: rbitcoin_net::NetPermTable,
    /// `--net-permission-relay` (default true): implicit relay on a bare CIDR grant.
    pub net_permission_relay: bool,
    /// `--net-permission-force-relay` (default false): implicit forcerelay on a bare CIDR grant.
    pub net_permission_force_relay: bool,
    /// `--startup-notify` shell command (run once after start).
    pub startup_notify: Option<String>,
    /// `--alert-notify` shell command (`%s` = warning text).
    pub alert_notify: Option<String>,
    /// `--min-chain-work` (32-byte BE work). `None` = no extra densify/relay floor.
    pub minimum_chain_work: Option<[u8; 32]>,
    /// `--mock-time` at start (`None` = wall clock).
    pub mock_time: Option<i64>,
    /// `--max-tip-age` seconds (`None` = 24h default on ChainHub).
    pub max_tip_age_secs: Option<u64>,
    /// `--block-version` GBT override (`None` = default).
    pub block_version: Option<i32>,
    /// `--block-min-tx-fee` as BTC/kvB text (`None` = default 1 sat/kvB).
    pub block_min_tx_fee_btc: Option<String>,
    /// BIP152 extra compact-block prefill (default **on**; `--prefill-compact=0` disables).
    pub prefill_compact: bool,
    /// `--check-blocks` window. `None` = store default (6). `<= 0` means the whole chain.
    pub check_blocks: Option<i64>,
    /// How often a down `--connect` / `addnode` target is tried again.
    /// Default [`rbitcoin_net::REDIAL_INTERVAL`]. Not a conf key; a test that
    /// waits for the redial sets [`rbitcoin_net::REDIAL_INTERVAL_TEST`].
    pub connect_redial: Duration,
    /// Unchanged-tip wait before one outbound full-relay peer is rotated.
    /// Default 600s. Not a conf key; a test sets a short wait.
    pub stale_tip: Duration,
    /// How often tip-follow checks [`Self::stale_tip`]. Default 60s.
    /// Not a conf key.
    pub stale_poll: Duration,
    /// `--trust-peer` as a [`rbitcoin_net::NetAddr`] (IP, onion, I2P, CJDNS).
    pub trust_peer: Option<rbitcoin_net::NetAddr>,
    /// `--trust-peer` clearnet DNS name. Mutually exclusive with [`Self::trust_peer`].
    pub trust_peer_host: Option<String>,
}

fn reject_trust_peer_listen(listen: &ListenOpts) -> Result<(), NodeError> {
    if !matches!(listen.p2p, P2pListen::Off) || listen.listen_onion || !listen.p2p_extra.is_empty()
    {
        return Err(NodeError::Config(
            "trust-peer cannot be combined with --listen".into(),
        ));
    }
    if listen.max_inbound > 0 {
        return Err(NodeError::Config(
            "trust-peer cannot be combined with --max-inbound greater than 0".into(),
        ));
    }
    if listen.use_seeds || !listen.seednodes.is_empty() {
        return Err(NodeError::Config(
            "trust-peer cannot be combined with --seed-node".into(),
        ));
    }
    Ok(())
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
            tor: TorControlOpts::default(),
            network: Network::Mainnet,
            signet_challenge: None,
            signet_block_time: None,
            smoke: false,
            hot_digest: false,
            assumehot: None,
            head_scale: HeadScale::Mainnet,
            max_run_secs: None,
            shindex: false,
            sh_force_rebuild: false,
            block_filter_index: false,
            prune_seqsigwit: false,
            datadir_hdd: false,
            prune_seqsigwit_ram_threshold_bytes: 256 * 1024 * 1024,
            bq_assign_stop_bytes: rbitcoin_query::BQ_ASSIGN_STOP_BYTES,
            sptweaks: false,
            sptweaks_dust: rbitcoin_electrum::DEFAULT_TWEAKS_MIN_DUST,
            max_sh_creates: rbitcoin_query::DEFAULT_MAX_SH_CREATES,
            heavy_sh_creates: rbitcoin_query::DEFAULT_HEAVY_SH_CREATES,
            electrum_max_subs: rbitcoin_electrum::DEFAULT_MAX_SCRIPTHASH_SUBS,
            esplora_max_inflight: rbitcoin_electrum::DEFAULT_MAX_CONNECTIONS,
            esplora_block_template: false,
            metrics: false,
            esplora_onion: true,
            sv2_tp_listen: None,
            sv2_tp_authority_sec: None,
            sv2_tp_cert_validity_secs: 3600,
            sv2_tp_stale_grace: Duration::from_secs(10),
            sv2_tp_idle_timeout: Duration::ZERO,
            sv2_tp_fee_delta: rbitcoin_sv2::FEE_DELTA,
            sv2_tp_template_interval: rbitcoin_sv2::TEMPLATE_INTERVAL,
            sv2_tp_constraints_cooldown: rbitcoin_sv2::CONSTRAINTS_COOLDOWN,
            milestone_height: 0,
            milestone_explicit: false,
            inhibit_suspend: false,
            conf_path: None,
            conf_log_level: None,
            api_log: None,
            asmap: None,
            uacomments: Vec::new(),
            test_activation_heights: Vec::new(),
            regtest_pow_bits: None,
            trusted: false,
            always_relay: false,
            relay: false,
            net_perms: rbitcoin_net::NetPermTable::default(),
            net_permission_relay: rbitcoin_net::DEFAULT_WHITELISTRELAY,
            net_permission_force_relay: rbitcoin_net::DEFAULT_WHITELISTFORCERELAY,
            startup_notify: None,
            alert_notify: None,
            minimum_chain_work: None,
            mock_time: None,
            max_tip_age_secs: None,
            block_version: None,
            block_min_tx_fee_btc: None,
            prefill_compact: true,
            check_blocks: None,
            connect_redial: rbitcoin_net::REDIAL_INTERVAL,
            stale_tip: Duration::from_secs(600),
            stale_poll: Duration::from_secs(60),
            trust_peer: None,
            trust_peer_host: None,
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
            .map_err(crate::error::NodeError::Init)
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
        self.listen.p2p = P2pListen::Socket(addr);
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
            return Milestone::NONE;
        }
        // Explicit `--milestone HEIGHT` stays height-only. The omitted mainnet
        // and testnet3 defaults also require the block hash at the default
        // height and min chain work.
        match default_milestone_anchor(self.network) {
            Some(anchor) if !self.milestone_explicit => Milestone {
                height: self.milestone_height,
                anchor: Some(anchor),
            },
            _ => Milestone::height(self.milestone_height),
        }
    }

    /// `--check-blocks` window. `0` = whole chain (store genesis walk).
    pub fn check_blocks_window(&self) -> u32 {
        match self.check_blocks {
            None => rbitcoin_store::VERIFY_TIP_BLOCKS,
            Some(n) if n <= 0 => 0,
            Some(n) => u32::try_from(n).unwrap_or(0),
        }
    }

    /// Implicit bits on a bare `--net-permission` CIDR grant.
    pub fn finalized_net_perms(&self) -> rbitcoin_net::NetPermTable {
        let mut t = self.net_perms.clone();
        for g in &mut t.whitelist {
            g.flags = rbitcoin_net::apply_implicit(
                g.flags,
                self.net_permission_relay,
                self.net_permission_force_relay,
            );
        }
        for g in &mut t.whitebind {
            g.flags = rbitcoin_net::apply_implicit(
                g.flags,
                self.net_permission_relay,
                self.net_permission_force_relay,
            );
        }
        t
    }

    #[doc(hidden)]
    pub fn push_p2p_listen(&mut self, addr: SocketAddr) -> Result<(), NodeError> {
        if self.listen.p2p == P2pListen::Socket(addr) || self.listen.p2p_extra.contains(&addr) {
            return Err(NodeError::Init("Duplicate binding configuration".into()));
        }
        if matches!(self.listen.p2p, P2pListen::Auto | P2pListen::Off) {
            self.listen.p2p = P2pListen::Socket(addr);
        } else {
            self.listen.p2p_extra.push(addr);
        }
        Ok(())
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
                    NodeError::Config(format!("test_activation_height {name}@{height}: {e}"))
                })?;
        }
        if let Some(bits) = self.regtest_pow_bits {
            params
                .apply_regtest_pow_bits(bits)
                .map_err(|e| NodeError::Config(format!("regtest_pow_bits: {e}")))?;
        }
        Ok(params)
    }

    pub fn validate(&self) -> Result<(), NodeError> {
        if self
            .mempool
            .block_reserved_sigops
            .is_some_and(|n| n > rbitcoin_consensus::block::MAX_BLOCK_SIGOPS_COST)
        {
            return Err(NodeError::Config(
                "block-reserved-sigops must be <= 80000".into(),
            ));
        }
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
            return Err(NodeError::Config("max-outbound must be >= 1".into()));
        }
        if (self.signet_challenge.is_some() || self.signet_block_time.is_some())
            && self.network != Network::Signet
        {
            return Err(NodeError::Config(
                "signet-challenge and signet-block-time require network=signet".into(),
            ));
        }
        if self.signet_block_time.is_some() && self.signet_challenge.is_none() {
            return Err(NodeError::Config(
                "signet-block-time requires signet-challenge".into(),
            ));
        }
        if self.signet_block_time == Some(0) {
            return Err(NodeError::Config(
                "signet-block-time must be greater than zero".into(),
            ));
        }
        if self.sptweaks && self.prune_seqsigwit {
            // Tweaks read input keys from scriptSig and witness (seqsigwit).
            return Err(NodeError::Config(
                "--sp-tweaks cannot be combined with --prune-seqsigwit: tweaks need the \
                 scriptSig and witness data pruning drops"
                    .into(),
            ));
        }
        if self.metrics && self.listen.health.is_none() {
            return Err(NodeError::Config("--metrics needs --health-listen".into()));
        }
        if self.rpc.rest && self.rpc.listen.is_none() && !self.rpc.socket {
            return Err(NodeError::Config(
                "--rest needs --rpc or --rpc-listen".into(),
            ));
        }
        if self.sv2_tp_listen.is_some() && self.sv2_tp_authority_sec.is_none() {
            return Err(NodeError::Config(
                "--sv2-tp-listen requires --sv2-tp-authority-sec or --sv2-tp-authority-sec-file"
                    .into(),
            ));
        }
        self.validate_only_net()?;
        self.validate_trust_peer()?;
        self.validate_hidden_inbound()?;
        self.validate_rpc_cookie()
    }

    /// True when `--trust-peer` named the sole dial target.
    pub fn trust_peer_set(&self) -> bool {
        self.trust_peer.is_some() || self.trust_peer_host.is_some()
    }

    /// Pin `--trust-peer` as the only dial target and refuse clashing flags.
    ///
    /// Runs from CLI assembly, before [`Self::ensure_datadir`] opens a store.
    pub fn seal_trust_peer(&mut self) -> Result<(), NodeError> {
        self.trust_peer_conflict()?;
        if !self.trust_peer_set() {
            return Ok(());
        }
        match (&self.trust_peer, &self.trust_peer_host) {
            (Some(addr), None) => {
                if self.listen.connect.is_empty() {
                    self.listen.connect.push(*addr);
                }
            }
            (None, Some(host)) => {
                if self.listen.connect_dns.is_empty() {
                    self.listen.connect_dns.push(host.clone());
                }
            }
            _ => {
                return Err(NodeError::Config(
                    "trust-peer accepts exactly one address".into(),
                ));
            }
        }
        self.listen.p2p = P2pListen::Off;
        self.listen.p2p_extra.clear();
        self.listen.listen_onion = false;
        self.listen.use_seeds = false;
        self.listen.max_inbound = 0;
        self.listen.seednodes.clear();
        Ok(())
    }

    fn trust_peer_conflict(&self) -> Result<(), NodeError> {
        if self.trust_peer.is_some() && self.trust_peer_host.is_some() {
            return Err(NodeError::Config(
                "trust-peer accepts exactly one address".into(),
            ));
        }
        if !self.trust_peer_set() {
            return Ok(());
        }
        if self.listen.listen_onion {
            return Err(NodeError::Config(
                "trust-peer cannot be combined with --listen-onion".into(),
            ));
        }
        if self.listen.p2p_explicit && !matches!(self.listen.p2p, P2pListen::Off) {
            return Err(NodeError::Config(
                "trust-peer cannot be combined with --listen".into(),
            ));
        }
        if self.listen.max_inbound_explicit && self.listen.max_inbound > 0 {
            return Err(NodeError::Config(
                "trust-peer cannot be combined with --max-inbound greater than 0".into(),
            ));
        }
        if !self.listen.seednodes.is_empty() {
            return Err(NodeError::Config(
                "trust-peer cannot be combined with --seed-node".into(),
            ));
        }
        self.connect_matches_trust_peer()
    }

    fn connect_matches_trust_peer(&self) -> Result<(), NodeError> {
        let clash =
            NodeError::Config("trust-peer cannot be combined with a different --connect".into());
        match (&self.trust_peer, &self.trust_peer_host) {
            (Some(addr), None)
                if !self.listen.connect_dns.is_empty()
                    || self.listen.connect.len() > 1
                    || self.listen.connect.iter().any(|a| a != addr) =>
            {
                return Err(clash);
            }
            (None, Some(host))
                if !self.listen.connect.is_empty()
                    || self.listen.connect_dns.len() > 1
                    || self
                        .listen
                        .connect_dns
                        .iter()
                        .any(|h| !h.eq_ignore_ascii_case(host)) =>
            {
                return Err(clash);
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_trust_peer(&self) -> Result<(), NodeError> {
        if !self.trust_peer_set() {
            return Ok(());
        }
        reject_trust_peer_listen(&self.listen)?;
        self.connect_matches_trust_peer()?;
        if self.listen.connect.is_empty() && self.listen.connect_dns.is_empty() {
            return Err(NodeError::Config("trust-peer requires an address".into()));
        }
        Ok(())
    }

    /// Check `--rpc-cookie-file` at startup. RPC itself only binds after
    /// catch-up, so a bad cookie found there would be a warning a day late.
    #[doc(hidden)]
    pub fn validate_rpc_cookie(&self) -> Result<(), NodeError> {
        let Some(path) = &self.rpc.cookie_file else {
            return Ok(());
        };
        if self.rpc.listen.is_none() && !self.rpc.listen_default {
            return Err(NodeError::Config(
                "--rpc-cookie-file applies to TCP only; add --rpc-listen".into(),
            ));
        }
        rbitcoin_rpc::read_cookie_file(path, self.rpc.cookie_perms)
            .map(drop)
            .map_err(NodeError::Config)
    }

    #[doc(hidden)]
    pub fn validate_only_net(&self) -> Result<(), NodeError> {
        if self.listen.only_net.contains(&rbitcoin_net::OnlyNet::Onion)
            && self.listen.proxy.is_none()
            && self.listen.onion.is_none()
        {
            return Err(NodeError::Config(
                "only-net=onion requires SOCKS (--proxy or --onion)".into(),
            ));
        }
        if self.listen.only_net.contains(&rbitcoin_net::OnlyNet::I2p)
            && self.listen.i2p_sam.is_none()
        {
            return Err(NodeError::Config(
                "only-net=i2p requires SAM (--i2p-sam)".into(),
            ));
        }
        if self.listen.only_net.contains(&rbitcoin_net::OnlyNet::Cjdns)
            && !self.listen.cjdns_reachable
        {
            return Err(NodeError::Config(
                "only-net=cjdns requires --cjdns-reachable".into(),
            ));
        }
        if self
            .listen
            .connect
            .iter()
            .any(|a| matches!(a, rbitcoin_net::NetAddr::Cjdns { .. }))
            && !self.listen.cjdns_reachable
        {
            return Err(NodeError::Config(
                "connect to a CJDNS address requires --cjdns-reachable".into(),
            ));
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn validate_hidden_inbound(&self) -> Result<(), NodeError> {
        if self.listen.i2p_accept_incoming {
            if self.listen.i2p_sam.is_none() {
                return Err(NodeError::Config(
                    "i2p-accept-incoming requires SAM (--i2p-sam)".into(),
                ));
            }
            if matches!(self.listen.p2p, P2pListen::Off) && !self.listen.listen_onion {
                return Err(NodeError::Config(
                    "i2p-accept-incoming needs a P2P listener (--listen); --listen=0 has no loopback to STREAM FORWARD"
                        .into(),
                ));
            }
        }
        if self.listen.listen_onion {
            if self.listen.max_inbound == 0 {
                return Err(NodeError::Config(
                    "listen-onion requires --max-inbound greater than 0".into(),
                ));
            }
            if self.tor.control.is_none() {
                return Err(NodeError::Config(
                    "listen-onion requires --tor-control".into(),
                ));
            }
        }
        Ok(())
    }

    /// Fill `--rpc-listen` omitted ADDR from `--network`. Implies unix socket.
    pub fn resolve_listen_defaults(&mut self) {
        if self.rpc.listen_default && self.rpc.listen.is_none() {
            self.rpc.listen = Some(SocketAddr::from((
                [127, 0, 0, 1],
                self.network.default_rpc_port(),
            )));
        }
        if self.rpc.listen.is_some() {
            self.rpc.socket = true;
        }
    }

    /// `{datadir}/rpc.token`.
    pub fn rpc_token_path(&self) -> PathBuf {
        self.rpc
            .token_file
            .clone()
            .unwrap_or_else(|| rbitcoin_rpc::default_token_path(self.datadir.path()))
    }

    /// Configured Core cookie file for TCP HTTP Basic authentication.
    pub fn rpc_cookie_path(&self) -> Option<PathBuf> {
        self.rpc.cookie_file.clone()
    }

    /// `--rpc-socket`, else `{datadir}/rpc.sock`.
    pub fn rpc_socket_path(&self) -> PathBuf {
        self.rpc
            .socket_path
            .clone()
            .unwrap_or_else(|| rbitcoin_rpc::default_socket_path(self.datadir.path()))
    }

    /// Owner-only mode for a directory this process just created.
    #[doc(hidden)]
    pub fn restrict_new_dir(path: &Path) -> Result<(), NodeError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
                |source| NodeError::Datadir {
                    path: path.to_path_buf(),
                    source,
                },
            )?;
        }
        #[cfg(not(unix))]
        {
            let _ = path;
        }
        Ok(())
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
        if created_root {
            Self::restrict_new_dir(root)?;
        }
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
            if created_cold {
                Self::restrict_new_dir(cold)?;
            }
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
    pub fn absorb_inbound_env(&mut self, env: &NodeEnv) {
        if self.listen.max_inbound_explicit {
            return;
        }
        if let Some(n) = env.p2p_max_inbound {
            self.listen.max_inbound = n;
        }
    }

    /// Load a simple `key=value` conf (`#` comments). Hyphens and underscores match.
    ///
    /// Operator keys are snake_case (`max_inbound=`). Hyphens match underscores.
    /// Core CLI names stay on the functional shim only.
    /// Repeatable: `net_permission`, `net_permission_bind`. Also `net_permission_relay`,
    /// `net_permission_force_relay`.
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
                    // Boolean flags: `no_seeds=1` preferred; bare `regtest`.
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
                        "conf {}:{}: expected key=value",
                        path.display(),
                        lineno + 1
                    )));
                }
            };
            let applied = match self.apply_kv(key, val) {
                Ok(v) => v,
                Err(NodeError::Config(msg)) => {
                    return Err(NodeError::Config(format!(
                        "conf {}:{}: {msg}",
                        path.display(),
                        lineno + 1
                    )));
                }
                Err(other) => return Err(other),
            };
            match applied {
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
}

/// BIP155 v3 onion: 56 lowercase base32 characters plus `.onion`.
fn v3_onion_host(val: &str) -> Option<String> {
    let name = val.strip_suffix(".onion")?;
    if name.len() != 56 {
        return None;
    }
    if !name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return None;
    }
    Some(val.to_string())
}

impl NodeConfig {
    /// Apply one conf / CLI-equivalent `key=value`. Unknown keys are not errors.
    pub fn apply_kv(&mut self, key: &str, val: &str) -> Result<ConfApply, NodeError> {
        let key_l = key.to_ascii_lowercase().replace('-', "_");
        match key_l.as_str() {
            "datadir" => self.datadir.path = PathBuf::from(val),
            "datadir_cold" => {
                if val.is_empty() {
                    return Err(NodeError::Config(
                        "conf datadir_cold requires a path".into(),
                    ));
                }
                self.datadir.cold = Some(PathBuf::from(val));
            }
            "network" => {
                self.network = Network::parse(val)
                    .map_err(|e| NodeError::Config(format!("conf network: {e}")))?;
            }
            "signet_challenge" => {
                self.signet_challenge = Some(
                    parse_signet_challenge(val)
                        .map_err(|e| NodeError::Init(format!("conf signet_challenge: {e}")))?,
                );
            }
            "signet_block_time" => {
                self.signet_block_time = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf signet_block_time: {e}")))?,
                );
            }
            "listen" => {
                self.listen.p2p_explicit = true;
                if is_listen_off(val) {
                    self.listen.p2p = P2pListen::Off;
                    self.listen.p2p_extra.clear();
                } else {
                    let addr: SocketAddr = val
                        .parse()
                        .map_err(|e| NodeError::Config(format!("conf listen: {e}")))?;
                    self.push_p2p_listen(addr)?;
                }
            }
            "no_listen" => {
                if parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf no_listen: {e}")))?
                {
                    self.listen.p2p_explicit = true;
                    self.listen.p2p = P2pListen::Off;
                    self.listen.p2p_extra.clear();
                }
            }
            "no_discover" => {
                self.listen.discover = !is_conf_true(val);
            }
            "only_net" => {
                self.listen.only_net.push(
                    rbitcoin_net::OnlyNet::parse(val)
                        .map_err(|e| NodeError::Config(format!("conf only_net: {e}")))?,
                );
            }
            "connect" => {
                push_connect(&mut self.listen, val)?;
            }
            "trust_peer" | "trustpeer" => {
                if self.trust_peer.is_some() || self.trust_peer_host.is_some() {
                    return Err(NodeError::Config(
                        "trust-peer accepts exactly one address".into(),
                    ));
                }
                match parse_connect_target("trust-peer", val)? {
                    ParsedConnect::Addr(addr) => self.trust_peer = Some(addr),
                    ParsedConnect::Dns(host) => self.trust_peer_host = Some(host),
                }
            }
            "head_scale" => {
                self.head_scale = match val {
                    "tiny" => HeadScale::Tiny,
                    "mainnet" => HeadScale::Mainnet,
                    other => {
                        return Err(NodeError::Config(format!(
                            "conf head_scale must be tiny or mainnet, got {other}"
                        )))
                    }
                };
            }
            "proxy" => {
                self.listen.proxy = Some(parse_required_socket(val, "proxy")?);
            }
            "onion" => {
                self.listen.onion = Some(parse_required_socket(val, "onion")?);
            }
            "tor_control" => {
                self.tor.control = Some(if val.is_empty() {
                    crate::tor_control::default_control_addr()
                } else {
                    parse_required_socket(val, "tor_control")?
                });
            }
            "tor_control_cookie" => {
                if val.is_empty() {
                    return Err(NodeError::Config(
                        "conf tor_control_cookie requires a path".into(),
                    ));
                }
                self.tor.cookie = Some(PathBuf::from(val));
            }
            "tor_control_password" => {
                if val.bytes().any(|b| b == b'\n' || b == b'\r' || b == 0) {
                    return Err(NodeError::Config(
                        "tor control password must not contain CR, LF, or NUL".into(),
                    ));
                }
                self.tor.password = Some(val.to_string());
            }
            "i2p_sam" => {
                self.listen.i2p_sam = Some(if val.is_empty() {
                    SocketAddr::from(([127, 0, 0, 1], 7656))
                } else {
                    parse_required_socket(val, "i2p_sam")?
                });
            }
            "i2p_accept_incoming" => {
                self.listen.i2p_accept_incoming = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf i2p_accept_incoming: {e}")))?;
            }
            "listen_onion" => {
                self.listen.listen_onion = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf listen_onion: {e}")))?;
            }
            "cjdns_reachable" => {
                self.listen.cjdns_reachable = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf cjdns_reachable: {e}")))?;
            }
            "proxy_randomize" => {
                self.listen.proxy_randomize = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf proxy_randomize: {e}")))?;
            }
            "seed_node" => {
                if !val.is_empty() {
                    if val.to_ascii_lowercase().contains(".onion") {
                        let _: rbitcoin_net::NetAddr = val
                            .parse()
                            .map_err(|e| NodeError::Config(format!("conf seed_node: {e}")))?;
                    }
                    self.listen.seednodes.push(val.to_string());
                }
            }
            "electrum_listen" => {
                self.listen.electrum = Some(if val.is_empty() {
                    SocketAddr::from(([127, 0, 0, 1], DEFAULT_ELECTRUM_PORT))
                } else {
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf electrum_listen: {e}")))?
                });
            }
            "esplora_listen" => {
                self.listen.esplora = Some(if val.is_empty() {
                    EsploraListen::Tcp(SocketAddr::from(([127, 0, 0, 1], DEFAULT_ESPLORA_PORT)))
                } else {
                    EsploraListen::parse(val, DEFAULT_ESPLORA_PORT)
                        .map_err(|e| NodeError::Config(format!("conf esplora_listen: {e}")))?
                });
            }
            "health_listen" => {
                self.listen.health = Some(if val.is_empty() {
                    SocketAddr::from(([127, 0, 0, 1], DEFAULT_HEALTH_PORT))
                } else {
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf health_listen: {e}")))?
                });
            }
            "sh_index" => {
                self.shindex = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf sh_index: {e}")))?;
            }
            "block_filter_index" => {
                self.block_filter_index = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf block_filter_index: {e}")))?;
            }
            "prune_seqsigwit" => {
                self.prune_seqsigwit = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf prune_seqsigwit: {e}")))?;
            }
            "datadir_hdd" => {
                self.datadir_hdd = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf datadir_hdd: {e}")))?;
            }
            "prune_seqsigwit_ram_threshold_bytes" => {
                self.prune_seqsigwit_ram_threshold_bytes = val.parse().map_err(|e| {
                    NodeError::Config(format!("conf prune_seqsigwit_ram_threshold_bytes: {e}"))
                })?;
            }
            "sp_tweaks" => {
                self.sptweaks = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf sp_tweaks: {e}")))?;
            }
            "sp_tweaks_dust" => {
                self.sptweaks_dust = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf sp_tweaks_dust: {e}")))?;
            }
            "max_sh_creates" => {
                self.max_sh_creates = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf max_sh_creates: {e}")))?;
            }
            "heavy_sh_creates" => {
                self.heavy_sh_creates = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf heavy_sh_creates: {e}")))?;
            }
            "electrum_max_subs" => {
                let n: usize = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf electrum_max_subs: {e}")))?;
                if n == 0 {
                    return Err(NodeError::Config(
                        "conf electrum_max_subs must be >= 1".into(),
                    ));
                }
                self.electrum_max_subs = n;
            }
            "esplora_max_inflight" => {
                let n: usize = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf esplora_max_inflight: {e}")))?;
                // `Semaphore::new` panics above `MAX_PERMITS`.
                if n == 0 || n > tokio::sync::Semaphore::MAX_PERMITS {
                    return Err(NodeError::Config(format!(
                        "conf esplora_max_inflight must be >= 1 and <= {}",
                        tokio::sync::Semaphore::MAX_PERMITS
                    )));
                }
                self.esplora_max_inflight = n;
            }
            "esplora_block_template" => {
                self.esplora_block_template = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf esplora_block_template: {e}")))?;
            }
            "esplora_onion" => {
                self.esplora_onion = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf esplora_onion: {e}")))?;
            }
            "sv2_tp_listen" => {
                self.sv2_tp_listen = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf sv2_tp_listen: {e}")))?,
                );
            }
            "sv2_tp_authority_sec" => {
                self.sv2_tp_authority_sec = Some(parse_authority_sec(&key_l, val)?);
            }
            // Keeps the secret out of argv and the unit file.
            "sv2_tp_authority_sec_file" => {
                let hex = std::fs::read_to_string(val).map_err(|e| {
                    // The path may be the key pasted into the wrong knob: never echo it.
                    NodeError::Config(format!("conf sv2_tp_authority_sec_file: {e}"))
                })?;
                self.sv2_tp_authority_sec = Some(parse_authority_sec(&key_l, hex.trim())?);
            }
            "sv2_tp_stale_grace" => {
                let max = rbitcoin_sv2::MAX_STALE_GRACE.as_secs();
                let secs = val
                    .parse()
                    .ok()
                    .filter(|&s: &u64| s <= max)
                    .ok_or_else(|| {
                        NodeError::Config(format!("conf sv2_tp_stale_grace: want seconds <= {max}"))
                    })?;
                self.sv2_tp_stale_grace = Duration::from_secs(secs);
            }
            "sv2_tp_idle_timeout" => {
                let max = rbitcoin_sv2::MAX_IDLE_TIMEOUT.as_secs();
                let secs = val
                    .parse()
                    .ok()
                    .filter(|&s: &u64| s <= max)
                    .ok_or_else(|| {
                        NodeError::Config(format!(
                            "conf sv2_tp_idle_timeout: want seconds <= {max}"
                        ))
                    })?;
                self.sv2_tp_idle_timeout = Duration::from_secs(secs);
            }
            "sv2_tp_fee_delta" => {
                self.sv2_tp_fee_delta = val
                    .parse()
                    .map_err(|_| NodeError::Config("conf sv2_tp_fee_delta: want sats".into()))?;
            }
            "sv2_tp_template_interval" => {
                let max = rbitcoin_sv2::MAX_TEMPLATE_INTERVAL.as_secs();
                let secs = val
                    .parse()
                    .ok()
                    .filter(|&s: &u64| (1..=max).contains(&s))
                    .ok_or_else(|| {
                        NodeError::Config(format!(
                            "conf sv2_tp_template_interval: want seconds in 1..={max}"
                        ))
                    })?;
                self.sv2_tp_template_interval = Duration::from_secs(secs);
            }
            "sv2_tp_cert_validity" => {
                self.sv2_tp_cert_validity_secs = val
                    .parse::<u32>()
                    .ok()
                    .filter(|&s| s > 0)
                    .ok_or_else(|| {
                        NodeError::Config(format!(
                            "conf sv2_tp_cert_validity: want seconds in 1..={}",
                            u32::MAX
                        ))
                    })?
                    .into();
            }
            "rpc" => {
                self.rpc.socket = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf rpc: {e}")))?;
            }
            "rpc_listen" => {
                self.rpc.socket = true;
                if val.is_empty() {
                    self.rpc.listen_default = true;
                } else {
                    self.rpc.listen = Some(
                        val.parse()
                            .map_err(|e| NodeError::Config(format!("conf rpc_listen: {e}")))?,
                    );
                }
            }
            "rpcuser" | "rpcpassword" => {
                return Err(NodeError::Config(
                    "rpcuser/rpcpassword removed; unix socket --rpc, Bearer {datadir}/rpc.token, \
                     or Core cookie --rpc-cookie-file"
                        .into(),
                ));
            }
            "rpc_socket" => {
                if val.is_empty() {
                    return Err(NodeError::Config("conf rpc_socket requires a path".into()));
                }
                self.rpc.socket = true;
                self.rpc.socket_path = Some(PathBuf::from(val));
            }
            "rpc_token_file" => {
                if val.is_empty() {
                    return Err(NodeError::Config(
                        "conf rpc_token_file requires a path".into(),
                    ));
                }
                self.rpc.token_file = Some(PathBuf::from(val));
            }
            "rpc_cookie_file" => {
                if val.is_empty() {
                    return Err(NodeError::Config(
                        "conf rpc_cookie_file requires a path".into(),
                    ));
                }
                self.rpc.cookie_file = Some(PathBuf::from(val));
            }
            "rpc_cookie_perms" => {
                self.rpc.cookie_perms =
                    rbitcoin_rpc::RpcCookiePerms::parse(val).map_err(NodeError::Config)?;
            }
            "ua_comment" => self.uacomments.push(val.to_string()),
            "test_activation_height" => {
                let (name, height) = ChainParams::parse_test_activation_height(val)
                    .map_err(|e| NodeError::Config(format!("conf test_activation_height: {e}")))?;
                self.test_activation_heights
                    .push((name.to_string(), height));
            }
            "regtest_pow_bits" => {
                self.regtest_pow_bits = Some(
                    ChainParams::parse_regtest_pow_bits(val)
                        .map_err(|e| NodeError::Config(format!("conf regtest_pow_bits: {e}")))?,
                );
            }
            "persist_mempool" => {
                self.mempool.persist = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf persist_mempool: {e}")))?;
            }
            "trusted" => {
                self.trusted = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf trusted: {e}")))?;
            }
            "always_relay" => {
                self.always_relay = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf always_relay: {e}")))?;
            }
            "relay" => {
                self.relay = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf relay: {e}")))?;
            }
            "net_permission" | "net_permissions" => {
                if !val.is_empty() {
                    let g = rbitcoin_net::parse_whitelist(val).map_err(NodeError::Init)?;
                    self.net_perms.whitelist.push(g);
                }
            }
            "net_permission_bind" => {
                if !val.is_empty() {
                    let g = rbitcoin_net::parse_whitebind(val).map_err(NodeError::Init)?;
                    if self.listen.p2p != P2pListen::Socket(g.addr)
                        && !self.listen.p2p_extra.contains(&g.addr)
                    {
                        self.push_p2p_listen(g.addr)?;
                    }
                    self.net_perms.whitebind.push(g);
                }
            }
            "net_permission_relay" => {
                self.net_permission_relay = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf net-permission-relay: {e}")))?;
            }
            "net_permission_force_relay" => {
                self.net_permission_force_relay = parse_conf_bool(val).map_err(|e| {
                    NodeError::Config(format!("conf net-permission-force-relay: {e}"))
                })?;
            }
            "blocks_only" => {
                self.mempool.blocksonly = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf blocks_only: {e}")))?;
            }
            "prefill_compact" => {
                self.prefill_compact = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf prefill_compact: {e}")))?;
            }
            "min_relay_tx_fee" => {
                if val.is_empty() {
                    return Err(NodeError::Config(
                        "conf min_relay_tx_fee requires a value".into(),
                    ));
                }
                parse_btc_to_sat(val)
                    .map_err(|e| NodeError::Config(format!("conf min_relay_tx_fee: {e}")))?;
                self.mempool.min_relay_fee_btc = Some(val.to_string());
            }
            "mempool_expiry" => {
                let h: u64 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf mempool_expiry: {e}")))?;
                self.mempool.expiry_hours = Some(h.max(1));
            }
            "startup_notify" => {
                if !val.is_empty() {
                    self.startup_notify = Some(val.to_string());
                }
            }

            "limit_cluster_count" => {
                self.mempool.limit_cluster_count =
                    Some(val.parse().map_err(|e| {
                        NodeError::Config(format!("conf limit_cluster_count: {e}"))
                    })?);
            }
            "bytes_per_sigop" => {
                self.mempool.bytes_per_sigop = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf bytes_per_sigop: {e}")))?,
                );
            }
            "block_reserved_sigops" => {
                self.mempool.block_reserved_sigops =
                    Some(val.parse().map_err(|e| {
                        NodeError::Config(format!("conf block_reserved_sigops: {e}"))
                    })?);
            }
            "limit_cluster_size" => {
                self.mempool.limit_cluster_size_kvb = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf limit_cluster_size: {e}")))?,
                );
            }
            "external_ip" => {
                if val.is_empty() {
                    return Err(NodeError::Config(
                        "conf external_ip requires an address".into(),
                    ));
                }
                if let Some(host) = v3_onion_host(val) {
                    self.listen.external_onions.push(host);
                } else {
                    let ip: std::net::IpAddr = val
                        .parse()
                        .map_err(|e| NodeError::Config(format!("conf external_ip: {e}")))?;
                    self.listen.external_ips.push(ip);
                }
            }
            "peer_timeout" => {
                let n: u64 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf peer_timeout: {e}")))?;
                if n == 0 {
                    return Err(NodeError::Init(
                        "peer-timeout must be a positive integer.".into(),
                    ));
                }
                self.listen.peer_timeout_secs = Some(n);
            }
            "min_chain_work" => {
                self.minimum_chain_work =
                    Some(parse_minimum_chain_work(val).map_err(NodeError::Init)?);
            }
            "milestone" => {
                self.milestone_height = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf milestone: {e}")))?;
                self.milestone_explicit = true;
            }
            "max_outbound" => {
                let n: u32 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf max_outbound: {e}")))?;
                if n == 0 {
                    return Err(NodeError::Config("conf max_outbound must be >= 1".into()));
                }
                self.listen.max_outbound = n;
            }
            "max_inbound" => {
                let n: u32 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf max_inbound: {e}")))?;
                self.listen.max_inbound = n;
                self.listen.max_inbound_explicit = true;
            }
            "mempool_size_mb" => {
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
            "api_log" => {
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
            "rpc_work_queue" => {
                let n: usize = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf rpc_work_queue: {e}")))?;
                self.rpc.work_queue = Some(if n == 0 {
                    rbitcoin_rpc::DEFAULT_RPC_WORK_QUEUE
                } else {
                    n
                });
            }
            "max_run_secs" => {
                self.max_run_secs = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf max_run_secs: {e}")))?,
                );
            }
            "metrics" => {
                self.metrics = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf metrics: {e}")))?;
            }
            "rest" => {
                self.rpc.rest = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf rest: {e}")))?;
            }
            "inhibit_suspend" => {
                self.inhibit_suspend = parse_conf_bool(val)
                    .map_err(|e| NodeError::Config(format!("conf inhibit_suspend: {e}")))?;
            }
            "mock_time" => {
                let n: i64 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf mock_time: {e}")))?;
                if n < 0 {
                    return Err(NodeError::Config("conf mock_time must be >= 0".into()));
                }
                self.mock_time = Some(n);
            }
            "check_blocks" => {
                let n: i64 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf check-blocks: {e}")))?;
                self.check_blocks = Some(n);
            }
            "max_tip_age" => {
                let n: i64 = val
                    .parse()
                    .map_err(|e| NodeError::Config(format!("conf max_tip_age: {e}")))?;
                if n < 0 {
                    return Err(NodeError::Config("conf max_tip_age must be >= 0".into()));
                }
                self.max_tip_age_secs = Some(n as u64);
            }
            "block_version" => {
                self.block_version = Some(
                    val.parse()
                        .map_err(|e| NodeError::Config(format!("conf block_version: {e}")))?,
                );
            }
            "block_min_tx_fee" => {
                if val.is_empty() {
                    return Err(NodeError::Config(
                        "conf block_min_tx_fee requires a value".into(),
                    ));
                }
                parse_btc_to_sat(val)
                    .map_err(|e| NodeError::Config(format!("conf block_min_tx_fee: {e}")))?;
                self.block_min_tx_fee_btc = Some(val.to_string());
            }
            "alert_notify" => {
                if !val.is_empty() {
                    self.alert_notify = Some(val.to_string());
                }
            }
            "no_seeds" => self.listen.use_seeds = !is_conf_true(val),
            "regtest" if is_conf_true(val) => self.network = Network::Regtest,
            "signet" if is_conf_true(val) => self.network = Network::Signet,
            "testnet" if is_conf_true(val) => self.network = Network::Testnet,
            _ => return Ok(ConfApply::Unknown(key.to_string())),
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

pub fn parse_signet_challenge(value: &str) -> Result<ScriptBuf, String> {
    Vec::<u8>::from_hex(value)
        .map(ScriptBuf::from_bytes)
        .map_err(|e| format!("must be hexadecimal: {e}"))
}

#[doc(hidden)]
pub fn parse_required_socket(val: &str, key: &str) -> Result<SocketAddr, NodeError> {
    if val.is_empty() {
        return Err(NodeError::Config(format!("conf {key}: empty")));
    }
    val.parse()
        .map_err(|e| NodeError::Config(format!("conf {key}: {e}")))
}

#[doc(hidden)]
pub fn is_listen_off(val: &str) -> bool {
    matches!(
        val.to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no"
    )
}

#[doc(hidden)]
pub fn is_conf_true(val: &str) -> bool {
    matches!(
        val.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | ""
    )
}

/// 64 hex, or SRI `key-utils` `Secp256k1SecretKey` base58check (the raw 32 bytes).
/// The error never echoes `val`: it is a secret.
#[doc(hidden)]
pub fn parse_authority_sec(key: &str, val: &str) -> Result<Sv2AuthoritySecret, NodeError> {
    <[u8; 32]>::from_hex(val)
        .ok()
        .or_else(|| bitcoin::base58::decode_check(val).ok()?.try_into().ok())
        .filter(|k| bitcoin::secp256k1::SecretKey::from_slice(k).is_ok())
        .map(Sv2AuthoritySecret)
        .ok_or_else(|| {
            NodeError::Config(format!(
                "conf {key}: want a secp256k1 secret key (64 hex or key-utils base58check)"
            ))
        })
}

/// Parse `1`/`true`/`yes`/`on` → true; `0`/`false`/`no`/`off` → false.
#[doc(hidden)]
pub fn parse_conf_bool(val: &str) -> Result<bool, String> {
    let v = val.to_ascii_lowercase();
    match v.as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("expected 0|1|true|false (got `{val}`)")),
    }
}

/// `--min-chain-work=<hex>` (optional `0x`, at most 64 hex digits).
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

#[doc(hidden)]
pub enum ParsedConnect {
    Addr(rbitcoin_net::NetAddr),
    Dns(String),
}

/// `--connect` / `--trust-peer` address grammar.
#[doc(hidden)]
pub fn parse_connect_target(key: &str, val: &str) -> Result<ParsedConnect, NodeError> {
    let val = val.trim();
    if val.is_empty() {
        return Err(NodeError::Config(format!(
            "conf {key} requires host[:port]"
        )));
    }
    if let Ok(addr) = val.parse::<rbitcoin_net::NetAddr>() {
        return Ok(ParsedConnect::Addr(addr));
    }
    let host = match val.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => host,
        _ => val,
    };
    let lower = host.to_ascii_lowercase();
    if lower.ends_with(".onion")
        || lower.ends_with(".b32.i2p")
        || val.contains(char::is_whitespace)
        || val.contains('/')
    {
        return Err(NodeError::Config(format!(
            "conf {key}: bad peer address {val}"
        )));
    }
    Ok(ParsedConnect::Dns(val.to_string()))
}

#[doc(hidden)]
pub fn push_connect(listen: &mut ListenOpts, val: &str) -> Result<(), NodeError> {
    match parse_connect_target("connect", val)? {
        ParsedConnect::Addr(addr) => listen.connect.push(addr),
        ParsedConnect::Dns(host) => listen.connect_dns.push(host),
    }
    Ok(())
}

impl NodeConfig {
    /// True when tip work meets `--min-chain-work` (or the flag is unset).
    pub fn meets_minimum_chain_work(&self, tip_work_be: [u8; 32]) -> bool {
        match self.minimum_chain_work {
            None => true,
            Some(min) => tip_work_be >= min,
        }
    }
}
