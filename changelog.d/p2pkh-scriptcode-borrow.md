Changed

- **The P2PKH fast path still hashes the scriptCode left after `FindAndDelete`.** It does not walk the script to do that. A signature that is the 20-byte pubkey hash hashes `OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG`. Every other signature hashes the 25-byte template, which `FindAndDelete` would leave unchanged.
