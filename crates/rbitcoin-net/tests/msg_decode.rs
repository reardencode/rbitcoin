use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::Magic;
use bitcoin::Network;
use rbitcoin_net::codec::FramedMessage;
use rbitcoin_net::msg_decode::*;
use std::sync::Arc;
use std::sync::Mutex;

fn verack_frame() -> FramedMessage {
    FramedMessage {
        magic: Magic::from(Network::Regtest),
        command: *b"verack\0\0\0\0\0\0",
        payload: Vec::new(),
    }
}

#[test]
fn decode_offload_light_and_spawn() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let msg = rt.block_on(decode_framed_offload(verack_frame())).unwrap();
    assert!(matches!(msg.payload(), NetworkMessage::Verack));

    let done = Arc::new(Mutex::new(false));
    let d2 = done.clone();
    rt.block_on(async {
        spawn_decode_then_with_err(
            verack_frame(),
            move |_| {
                *d2.lock().unwrap() = true;
            },
            |_| panic!("should not err"),
        );
        // Yield so the spawned task can finish.
        tokio::task::yield_now().await;
        for _ in 0..50 {
            if *done.lock().unwrap() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    });
    assert!(*done.lock().unwrap());
}

#[test]
fn decode_permit_pools_are_wider_than_one_slot() {
    let blocks = block_decode_permits();
    let ctrl = ctrl_decode_permits();
    let pool = blocking_pool_size();
    assert_eq!(blocks, pool, "block decodes match the blocking pool");
    assert!(
        ctrl <= pool,
        "header decodes cannot exceed the pool, got {ctrl}"
    );
    assert!(ctrl >= 1);
}

#[test]
fn decode_permits_follow_the_pool_for_a_fixed_core_count() {
    // 4 cores: pool floor is 4, so both permits are 4 (header formula is 8, capped).
    assert_eq!(blocking_pool_size_for(Some(4)), 4);
    assert_eq!(block_decode_permits_for(Some(4)), 4);
    assert_eq!(ctrl_decode_permits_for(Some(4)), 4);
    // 1 core still floors the pool at 4. Header permits stay within that floor
    // and within max(cores * 2, 8).
    assert_eq!(blocking_pool_size_for(Some(1)), 4);
    assert_eq!(block_decode_permits_for(Some(1)), 4);
    assert_eq!(ctrl_decode_permits_for(Some(1)), 4);
    assert!(ctrl_decode_permits_for(Some(1)) <= 1usize.saturating_mul(2).max(8));
    // 16 cores: block permits are the pool (16). Header permits are min(32, 16).
    assert_eq!(block_decode_permits_for(Some(16)), 16);
    assert_eq!(ctrl_decode_permits_for(Some(16)), 16);
    assert!(ctrl_decode_permits_for(Some(16)) <= 16usize.saturating_mul(2).max(8));
    // Unknown parallelism uses the pool floor, not the old 64-wide block queue.
    assert_eq!(block_decode_permits_for(None), 4);
    assert_eq!(ctrl_decode_permits_for(None), 4);
}
