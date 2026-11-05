Changed

- **The P2PKH fast path no longer walks the script for `FindAndDelete`.** On the 25-byte template the signature push matches only when it is the 20-byte pubkey hash. Every other signature hashes the script in place.
