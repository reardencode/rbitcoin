Changed

- **Block validation batch-verifies Taproot signatures and tweak checks.** Block script checks queue Taproot key-path signatures, tapscript signatures, and control-block tweak checks for each chunk of up to 32 transactions, then verify them in one batch. The batch code is the libsecp256k1 batch module from bitcoin-core/secp256k1 PR #1134, vendored in `rbitcoin-secp256k1-batch` because upstream has not merged it. When a batch fails, the chunk is checked again one signature at a time, so errors still name the failing input. Mempool and RPC checks are unchanged.
