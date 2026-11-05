Fixed

- **A taproot script-path tweak at or above the curve order fails the commitment check.** `TapTweakHash::to_scalar` panics on those 32 bytes. The check now returns the same witness-program mismatch Core returns from `CheckTapTweak`.
- **The P2PKH fast path hashes the scriptCode left after `FindAndDelete`.** When the signature is the 20-byte pubkey hash, that is the same script the interpreter hashes.
