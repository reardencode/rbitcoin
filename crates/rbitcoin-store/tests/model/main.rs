#![cfg(any(loom, shuttle))]
//! Model-checked `ArrayTable` races: one writer, flushers, and readers over
//! an in-memory file. loom explores every interleaving up to a preemption
//! bound; shuttle samples PCT and random schedules. Empty under the default
//! cfg.
//!
//! Run: `./scripts/model-check.sh loom` or `./scripts/model-check.sh shuttle`.

mod array_table;
mod engine;
mod mem_file;
