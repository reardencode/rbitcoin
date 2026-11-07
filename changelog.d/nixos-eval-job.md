Changed

- **NixOS module eval is its own CI job.** `nixos-module-eval` no longer runs at the end of `qc`, so `coverage`, `pread`, and `rust-forward` do not wait on it. Assertion and argv checks evaluate the rbitcoin module without a full NixOS system for each case.
