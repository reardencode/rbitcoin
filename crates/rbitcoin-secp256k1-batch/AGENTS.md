# rbitcoin-secp256k1-batch

Safe wrapper over the libsecp256k1 batch verification module
(bitcoin-core/secp256k1 PR #1134, not merged upstream). Used only by
`rbitcoin-consensus` for block script checks.

## Where

- Vendored C: `depend/secp256k1/`. Do not hand-edit. Re-run
  `./vendor-libsecp.sh [REV]`; the pinned revision is in
  `depend/secp256k1-HEAD-revision.txt`.
- Wrapper: `src/lib.rs`. Symbols carry an `rbtc_secp256k1_` prefix.
- Nix keeps `depend/` through the filter in `nix/rbitcoin.nix`.

## Verify

`cargo test -p rbitcoin-secp256k1-batch`
