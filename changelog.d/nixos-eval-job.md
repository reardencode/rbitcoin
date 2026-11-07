Changed

- **NixOS module eval is its own CI job.** `nixos-module-eval` starts with `pread` and `rust-forward`, after `qc` and `test`, and does not gate `coverage`. Assertion and argv checks evaluate the rbitcoin module without a full NixOS system for each case.
