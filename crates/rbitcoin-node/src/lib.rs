//! Node lifecycle, configuration, and process orchestration.

mod cli;
mod config;
mod error;
mod health;
mod inhibit;
mod lock;
mod regtest_rpc;
mod run;
mod tor_control;

pub use cli::cli_main;
pub use config::{
    DatadirOpts, ListenOpts, MempoolOpts, NodeConfig, P2pListen, RpcOpts, Sv2AuthoritySecret,
    TorControlOpts,
};
pub use error::NodeError;
pub use run::{run_node, run_p2p, NodeHandle};
