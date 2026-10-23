Added

- The default signet enforces the BIP 448 tapscript opcodes at the
  Bitcoin Inquisition buried heights: `OP_CHECKSIGFROMSTACK` and
  `OP_INTERNALKEY` from 272592, `OP_TEMPLATEHASH` from 314928. Regtest
  enables all three at every height. Mainnet, testnet, and a custom
  signet stay off. While a deployment is off, its byte is still
  `OP_SUCCESS`.
