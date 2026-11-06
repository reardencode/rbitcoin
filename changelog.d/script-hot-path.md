Changed

- A script check resolves each spent output once and records at job build whether the transaction needs BIP143 midstates.
- Native P2WPKH borrows the pubkey hash and reads the witness once.
