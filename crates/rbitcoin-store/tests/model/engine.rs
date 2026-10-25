//! One `check` for both model checkers. The constants are the CI budget; a
//! deep run raises it through the environment.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Exhaustive search of a two-flusher model runs for minutes; three
/// preemptions per execution finish each model in under a second.
#[cfg(loom)]
const DEFAULT_PREEMPTIONS: usize = 3;

#[cfg(shuttle)]
const SEED: u64 = 0x5eed_a77a_7ab1_e5ee;
#[cfg(shuttle)]
const PCT_DEPTH: usize = 3;
#[cfg(shuttle)]
const PCT_ITERS: usize = 50_000;
#[cfg(shuttle)]
const RANDOM_ITERS: usize = 50_000;

/// Every interleaving of `f` with at most [`DEFAULT_PREEMPTIONS`]
/// preemptions. `LOOM_MAX_PREEMPTIONS` overrides the bound;
/// `MODEL_LOOM_EXHAUSTIVE=1` removes it.
#[cfg(loom)]
pub fn check(f: impl Fn() + Send + Sync + 'static) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = match env::<u8>("MODEL_LOOM_EXHAUSTIVE") {
        Some(1) => None,
        _ => builder.preemption_bound.or(Some(DEFAULT_PREEMPTIONS)),
    };
    counted(f, |f| builder.check(move || f()));
}

/// A PCT run, then a uniform random run, from one seed.
/// `SHUTTLE_RANDOM_SEED` overrides the seed, `MODEL_SHUTTLE_ITERS` the
/// iteration count of each run, `MODEL_SHUTTLE_DEPTH` the PCT depth.
#[cfg(shuttle)]
pub fn check(f: impl Fn() + Send + Sync + 'static) {
    use shuttle::scheduler::{PctScheduler, RandomScheduler};
    let iters = env("MODEL_SHUTTLE_ITERS");
    let depth = env("MODEL_SHUTTLE_DEPTH").unwrap_or(PCT_DEPTH);
    counted(f, |f| {
        let pct = Arc::clone(&f);
        let pct_iters = iters.unwrap_or(PCT_ITERS);
        shuttle::Runner::new(
            PctScheduler::new_from_seed(SEED, depth, pct_iters),
            config(),
        )
        .run(move || pct());
        let random = RandomScheduler::new_from_seed(SEED, iters.unwrap_or(RANDOM_ITERS));
        shuttle::Runner::new(random, config()).run(move || f());
    });
}

#[cfg(shuttle)]
fn config() -> shuttle::Config {
    let mut config = shuttle::Config::new();
    // The Release/Acquire orderings are intentional; shuttle runs every
    // atomic as SeqCst and would warn on each.
    config.silence_warnings = true;
    config
}

fn env<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

/// Runs `explore` over `f` and prints how many executions it took (shown
/// with `--nocapture` or on failure).
fn counted<F: Fn() + Send + Sync + 'static>(
    f: F,
    explore: impl FnOnce(Arc<dyn Fn() + Send + Sync>),
) {
    let runs = Arc::new(AtomicUsize::new(0));
    let start = std::time::Instant::now();
    let seen = Arc::clone(&runs);
    explore(Arc::new(move || {
        seen.fetch_add(1, Ordering::Relaxed);
        f();
    }));
    let runs = runs.load(Ordering::Relaxed);
    eprintln!("model: {runs} executions in {:.1?}", start.elapsed());
}
