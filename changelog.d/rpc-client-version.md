Added

- **`--rpc-client-version N`** (conf `rpc_client_version=`, 1 to 1000000)
  sets the integer `getnetworkinfo.version` reports. The default stays
  190000, so existing clients keep the Core 0.19 response shapes. Only the
  integer changes; no RPC is added. Bark's captaind will not start below
  310000, so an operator running it sets `--rpc-client-version=310000`.
