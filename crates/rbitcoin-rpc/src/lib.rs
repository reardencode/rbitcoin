//! Core-class JSON-RPC HTTP server (documented subset — not full Core parity).
//!
//! See `docs/rpc.md` for methods, auth, and permanent gaps.

mod auth;
mod blockstats;
mod methods;
mod server;

pub use auth::RpcAuth;
pub use methods::{submit_received_block, RpcActive, RpcRegtest, SubmitBlockOutcome};
pub use server::{run_rpc, RpcConfig, RpcHandle};

/// Root HTTP path for the node RPC endpoint.
pub fn node_rpc_path() -> &'static str {
    "/"
}

#[cfg(test)]
mod tests {
    #[test]
    fn node_rpc_path_is_root() {
        assert_eq!(crate::node_rpc_path(), "/");
    }
}
