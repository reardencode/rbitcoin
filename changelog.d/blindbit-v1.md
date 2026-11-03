Added

- **BlindBit oracle v1 over HTTP.** With `--sp-tweaks`, the Esplora listener serves `/blindbit/v1/` for silent-payment wallets on the BlindBit v1 backend (Dana): `info`, `block-height`, `block-hash`, `tweaks` and `tweak-index` with `dustLimit`, `utxos`, both BIP158 filters, `spent-index`, and `forward-tx`.
- **Filters and the spent index are built for that request.** They come from the block's own outputs and the inputs it spends. The request does not read the parent outputs, and nothing new is stored.
- **Those routes share one limit of requests in flight.** The limit is half the blocking pool, and it is taken before a listener slot, so a wallet rescan does not fill the listener.
