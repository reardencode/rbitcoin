Added

- **Container image and aarch64 Linux binaries.** Each release tag
  publishes `ghcr.io/reardencode/rbitcoin` (and Docker Hub
  `reardencode/rbitcoin` once enabled) for `linux/amd64` and
  `linux/arm64`: the Release musl binaries on `FROM scratch`, running as
  uid 10001 with the datadir at `/data/datadir`. Tags are `X.Y.Z`, `X.Y`,
  and `latest`; a patch on an older line does not move `latest`. The
  GitHub Release adds static musl
  `rbitcoin-{node,cli}-aarch64-linux` and `SHA256SUMS.linux-musl-aarch64`,
  built on a native arm64 runner. Each arch's image is booted on regtest
  before the Release is created. Run notes: `docs/operator/setup.md`.
