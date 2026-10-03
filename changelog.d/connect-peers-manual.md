Fixed

- **`--connect` peers are `manual`, as in Core.** `getpeerinfo` reported a
  `--connect` peer as `outbound-full-relay`. Core counts `manual` peers as
  preferred download peers, and so does this node now: one whose outbound
  peers all come from `--connect` or `addnode` replaces a stalling
  headers-sync peer instead of waiting on it. As in Core, a `--connect` peer
  is no longer dropped for missing `NODE_NETWORK`, and `--seednode` is not
  dialled under `--connect`.
