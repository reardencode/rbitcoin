#![allow(unused_imports)]
//! OS name of the IBD header thread.

use rbitcoin_ibd::ibd::published::IBD_HEADER_THREAD_NAME;
use rbitcoin_ibd::ibd::{empty_header_fk_bus, spawn_header_thread, IbdWorkState};
use rbitcoin_store::HeaderThreadProbe;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// `ps` / `top` show this thread as `ibd-header` for the whole catch-up.
#[cfg(target_os = "linux")]
#[test]
fn header_thread_comm_is_ibd_header() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-header-name");
    let hub = Arc::new(hub);
    let state = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let join = spawn_header_thread(
        Arc::new(Mutex::new(state)),
        hub,
        rx,
        empty_header_fk_bus(),
        HeaderThreadProbe::new(),
    );
    assert_eq!(IBD_HEADER_THREAD_NAME, "ibd-header");
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut comms = linux_task_comms();
    while Instant::now() < deadline && !comms.iter().any(|name| name == IBD_HEADER_THREAD_NAME) {
        std::thread::sleep(Duration::from_millis(10));
        comms = linux_task_comms();
    }
    drop(tx);
    join.join().expect("header thread");
    drop(dir);
    assert!(
        comms.iter().any(|name| name == IBD_HEADER_THREAD_NAME),
        "header thread comm is {IBD_HEADER_THREAD_NAME}, saw {comms:?}"
    );
}

#[cfg(target_os = "linux")]
fn linux_task_comms() -> Vec<String> {
    let mut names = Vec::new();
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return names;
    };
    for task in tasks.flatten() {
        let path = task.path().join("comm");
        if let Ok(raw) = std::fs::read_to_string(path) {
            names.push(raw.trim_end_matches('\n').to_string());
        }
    }
    names
}
