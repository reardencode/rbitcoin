/// Arm the tip-accept lane permit before any test thread starts. A node
/// binary does not link this suite, so production never takes that lock.
#[used]
#[cfg_attr(
    any(target_os = "linux", target_os = "android", target_os = "freebsd"),
    link_section = ".init_array"
)]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XCU")]
static ENABLE_LANE_TEST_GATE: extern "C" fn() = {
    extern "C" fn enable() {
        rbitcoin_net::tip_accept::enable_lane_test_gate();
    }
    enable
};

mod asmap;
mod cache;
mod chain;
mod codec;
mod compact;
mod ephemeral;
mod error;
mod eviction;
mod fee_history;
mod fee_history_file;
mod i2p_sam;
#[cfg(windows)]
mod listen;
mod most_work;
mod msg_decode;
mod net_permissions;
mod netaddr;
mod netgroup;
mod parent_req;
mod peer;
mod peer_dos;
mod peers;
mod perf_meter;
mod root;
mod seeds;
mod service;
mod socks;
mod tip_accept;
mod tx_relay;
mod v1;
mod v2;
mod versionbits_warn;
