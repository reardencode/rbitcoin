Fixed

- **WITNESS and TAPROOT script flags apply on every block, as in Core.**
  They no longer wait for the segwit or taproot height. Core's two
  mainnet exception blocks keep their replacement sets: the BIP16
  exception (170060) runs with no P2SH, WITNESS, or TAPROOT, and block
  692261 runs without TAPROOT.
  Witness sigops count on every block with the WITNESS flag. On a regtest
  chain with a later `-testactivationheight=segwit@N`, a v0 witness
  program spend below `N` is now held to the witness rules.
- **P2PKH spends enforce the 520-byte push limit.** The P2PKH fast path
  accepted a scriptSig push over 520 bytes (for example a pre-BIP66
  signature with junk before the hashtype). It now falls back to the
  interpreter, which rejects it as Core does.
- **P2WPKH signatures follow the DERSIG flag.** The P2WPKH fast path
  (native and P2SH-nested) required strict DER on every block. Core
  applies strict DER to v0 witness signatures only when BIP66 is active,
  and caps each witness element at 520 bytes. Both now match Core; this
  shows on a regtest chain with dersig activated after segwit.
