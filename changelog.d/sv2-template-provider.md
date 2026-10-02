Added

- **Stratum v2 Template Provider.** `--sv2-tp-listen ADDR` serves the
  SV2 Template Distribution Protocol over Noise. A JDC or pool gets a
  template on every tip, can fetch its transactions, and can submit a
  solved block, which the node accepts like any other block.
  `--sv2-tp-authority-sec-file` (or `--sv2-tp-authority-sec`) sets the
  signing key. `--sv2-tp-cert-validity` and `--sv2-tp-stale-grace` tune
  the certificates and old-tip templates. NixOS:
  `services.rbitcoin.sv2.tp.*`. Default off.
