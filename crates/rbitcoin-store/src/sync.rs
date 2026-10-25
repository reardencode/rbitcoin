//! `std::sync` behind one import. `--cfg loom` / `--cfg shuttle` swap in the
//! model checker's primitives; production is `std`.

#[cfg(all(loom, shuttle))]
compile_error!("--cfg loom and --cfg shuttle are exclusive");

#[cfg(loom)]
pub use loom::{
    sync::{atomic, Arc, Mutex, RwLock},
    thread,
};

#[cfg(shuttle)]
pub use shuttle::{
    sync::{atomic, Arc, Mutex, RwLock},
    thread,
};

#[cfg(not(any(loom, shuttle)))]
pub use std::{
    sync::{atomic, Arc, Mutex, RwLock},
    thread,
};

/// The model checkers' atomics still spell `try_update` as `fetch_update`.
/// TODO: remove once tokio-rs/loom#429 and awslabs/shuttle#405 land.
#[cfg(any(loom, shuttle))]
pub trait TryUpdate<T> {
    fn try_update(
        &self,
        set: atomic::Ordering,
        fetch: atomic::Ordering,
        f: impl FnMut(T) -> Option<T>,
    ) -> Result<T, T>;
}

#[cfg(any(loom, shuttle))]
impl TryUpdate<u64> for atomic::AtomicU64 {
    fn try_update(
        &self,
        set: atomic::Ordering,
        fetch: atomic::Ordering,
        f: impl FnMut(u64) -> Option<u64>,
    ) -> Result<u64, u64> {
        self.fetch_update(set, fetch, f)
    }
}
