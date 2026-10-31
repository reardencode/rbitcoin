//! Off-thread P2P payload decode so socket tasks stay I/O-bound.
//!
//! Async peer readers call [`crate::v2::read_v2_frame`] then hand the
//! [`FramedMessage`] to [`decode_framed_offload`]. That runs
//! [`FramedMessage::decode`] on Tokio's **blocking** pool (OS threads), freeing
//! multi-thread runtime workers to poll other sockets.
//!
//! A process-wide semaphore bounds how many decodes enter the blocking pool.
//! Frames already read and waiting on a permit are capped per peer in the
//! session loop. The permit is acquired after the frame is already owned by
//! the decode task, so the reader does not wait before the next TCP read.

use crate::codec::FramedMessage;
use crate::error::NetError;
use bitcoin::p2p::message::RawNetworkMessage;
use std::sync::{Arc, OnceLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Floor for the Tokio blocking pool and for decode permits. Electrum re-exports
/// this so `batch_window` and the node runtime share one constant.
pub const MIN_BLOCKING_POOL: usize = 4;

/// Blocking-pool size for a known core count. `None` is the floor (parallelism
/// could not be read). Never below [`MIN_BLOCKING_POOL`].
#[doc(hidden)]
pub fn blocking_pool_size_for(parallelism: Option<usize>) -> usize {
    parallelism
        .unwrap_or(MIN_BLOCKING_POOL)
        .max(MIN_BLOCKING_POOL)
}

#[doc(hidden)]
pub fn blocking_pool_size() -> usize {
    blocking_pool_size_for(std::thread::available_parallelism().ok().map(|n| n.get()))
}

#[doc(hidden)]
pub fn block_decode_permits_for(parallelism: Option<usize>) -> usize {
    blocking_pool_size_for(parallelism)
}

#[doc(hidden)]
pub fn block_decode_permits() -> usize {
    block_decode_permits_for(std::thread::available_parallelism().ok().map(|n| n.get()))
}

/// Concurrent **headers/notfound** decodes. At most `max(cores * 2, 8)` and
/// never more than the blocking pool, so a header storm cannot take block
/// permits or outnumber pool threads.
#[doc(hidden)]
pub fn ctrl_decode_permits_for(parallelism: Option<usize>) -> usize {
    let cores = parallelism.unwrap_or(1);
    let uncapped = cores.saturating_mul(2).max(8);
    uncapped.min(blocking_pool_size_for(parallelism))
}

#[doc(hidden)]
pub fn ctrl_decode_permits() -> usize {
    ctrl_decode_permits_for(std::thread::available_parallelism().ok().map(|n| n.get()))
}

#[doc(hidden)]
pub fn block_decode_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(block_decode_permits())))
}

#[doc(hidden)]
pub fn ctrl_decode_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(ctrl_decode_permits())))
}

/// Decode a framed message on the blocking pool.
///
/// Acquires a decode permit first so IBD cannot enqueue more decodes than the
/// blocking pool has threads. The frame is already in this task; waiting here
/// does not shrink getdata-window RAM. Blocks and headers use separate
/// semaphores so getheaders spam cannot take block permits. The calling async
/// task **awaits** the permit and the join, but does **not** run CPU work on a
/// multi-thread worker. The reader must not await this permit before the next
/// TCP read.
pub async fn decode_framed_offload(frame: FramedMessage) -> Result<RawNetworkMessage, NetError> {
    if frame.is_block() {
        let permit = block_decode_semaphore()
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| NetError::Protocol("decode semaphore closed"))?;
        decode_with_permit(frame, permit).await
    } else if frame.decode_is_cpu_heavy() {
        let permit = ctrl_decode_semaphore()
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| NetError::Protocol("decode semaphore closed"))?;
        decode_with_permit(frame, permit).await
    } else {
        // Tiny messages (verack, ping already handled, sendheaders, …): cheap
        // enough that a spawn_blocking round-trip is pure overhead. Still keep
        // this path free of multi-MB work.
        frame.try_decode()
    }
}

pub async fn decode_with_permit(
    frame: FramedMessage,
    permit: OwnedSemaphorePermit,
) -> Result<RawNetworkMessage, NetError> {
    let msg = tokio::task::spawn_blocking(move || {
        let msg = frame.try_decode();
        drop(permit);
        msg
    })
    .await
    .map_err(|_| NetError::Protocol("decode task join failed"))??;
    Ok(msg)
}

/// Fire-and-forget heavy decode: free the reader immediately after framing.
///
/// Used by IBD peer readers so one slow `block` deserialize never blocks the
/// next TCP read on that peer. `on_done` runs on the async runtime after decode
/// (keep it light — only channel sends). `on_err` runs if decode fails
/// (join / semaphore / oversize headers).
///
/// **Invariant:** readers must not await a decode permit (or any other soft
/// body-queue gate) before the next TCP read. Soft BQ depth is enforced
/// only by stopping new block *requests* (getdata assign), never by
/// refusing to read or decode data a peer already sends for a prior request.
pub fn spawn_decode_then_with_err<F, E>(frame: FramedMessage, on_done: F, on_err: E)
where
    F: FnOnce(RawNetworkMessage) + Send + 'static,
    E: FnOnce(NetError) + Send + 'static,
{
    tokio::spawn(async move {
        match decode_framed_offload(frame).await {
            Ok(msg) => on_done(msg),
            Err(e) => on_err(e),
        }
    });
}
