Fixed

- **WITNESS and TAPROOT script flags apply on every block, as in Core.**
  They no longer wait for the segwit or taproot height. Core's two
  mainnet exception blocks keep their replacement sets: the BIP16
  exception (170060) runs with no P2SH, WITNESS, or TAPROOT, and block
  692261 runs without TAPROOT.
  Witness sigops count on every block with the WITNESS flag. On a regtest
  chain with a later `-testactivationheight=segwit@N`, a v0 witness
  program spend below `N` is now held to the witness rules.
