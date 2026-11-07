Changed

- **NixOS module eval is its own CI job.** `nixos-module-eval` starts with `pread` and `rust-forward`, after `qc` and `test`, and does not gate `coverage`. It does not block merge until the Protected ruleset names that check. Assertion and argv checks evaluate the rbitcoin module without a full NixOS system for each case. The unix-socket argv is checked against a real NixOS `ExecStart`.
