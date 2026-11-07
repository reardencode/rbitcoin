Fixed

- **`--locked` builds work again** (#1448). `Cargo.lock` still listed the
  workspace crates at `0.8.99` after the 0.9.0 cut and the move to `0.9.99`,
  so `cargo build --locked` and `cargo install --locked` refused the lock. The
  `qc` job now runs `cargo metadata --locked`, so a release bump that leaves
  the lock behind fails CI.
