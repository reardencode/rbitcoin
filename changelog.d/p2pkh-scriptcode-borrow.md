Changed

- **The P2PKH fast path still hashes the post-`FindAndDelete` scriptCode, without walking the script.** A signature that is the 20-byte pubkey hash still hashes `OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG`. Every other signature still hashes the 25-byte template, which `FindAndDelete` would leave unchanged.
