Added

- **btc-lean consensus census is vendored and anchored.** `third_party/btc-lean` pins Rob1Ham/btc-lean. Each rule in that pin's `spec/db/rules.yaml` has a `// btc-lean:` comment on the statement that implements or tests it, or a reason in `docs/btc-lean-gaps.md`. `status: obsolete` needs no comment. The `qc` job checks the pin against the comments and that file.
