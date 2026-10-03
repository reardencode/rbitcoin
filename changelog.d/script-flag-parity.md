Fixed

Script engine behaviour under policy flags now matches Core. Mempool
admission does not change: it still runs with consensus flags only.

- **NULLFAIL in witness v0 `CHECKMULTISIG` applies after the key walk.**
  A P2WSH multisig signature that matches a later key is no longer
  rejected when NULLFAIL is set.
- **STRICTENC and WITNESS_PUBKEYTYPE check the pubkey for an empty
  signature**, in `CHECKSIG` and in each `CHECKMULTISIG` pair checked.
- **DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM matches Core.** Pay-to-anchor
  and a v1 32-byte program before Taproot are exempt. P2SH-wrapped
  v1+ programs are discouraged.
- **P2WPKH applies LOW_S and the STRICTENC hashtype check** when those
  flags are set, native and P2SH-wrapped.
