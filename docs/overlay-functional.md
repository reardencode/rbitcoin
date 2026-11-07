# Overlay functional harness (private meshes)

Private Tor, i2pd, and cjdns daemons on the runner. Product journeys use the
same operator sockets a home node uses (SOCKS, Tor control cookie, SAM,
`fc00::/8` on a real TUN). This job is the live-daemon oracle
([`TESTING.md`](../TESTING.md)).

Default `cargo test --workspace` never builds the overlay test binary
(`required-features = ["overlay"]`). Do not add `#[ignore]` overlay tests
to the default suite.

Owner of daemon pins, env vars, walls, and the private-mesh rule. Skill:
[`.agents/skills/overlay-functional/SKILL.md`](../.agents/skills/overlay-functional/SKILL.md).

## Private mesh (no public overlays)

GitHub Actions starts:

| Mesh | How | Must not |
|------|-----|----------|
| Tor | TestingTorNetwork (chutney `basic-min` equivalent: dirauths + client). `AssumeReachable`, short voting. Client SOCKS + control cookie. | Bootstrap public Tor / public HSDir wait |
| i2pd | Six floodfills, **`netid` 16** (not mainnet 2), empty `reseed.urls`, zip-seeded RouterInfos, NTCP2 on `127.0.0.0/8` (`/32` aliases), exploratory tunnels length 1, SAM on n0/n1 | Public I2P reseed / netid 2 |
| cjdns | Two `cjdroute` processes, UDP peer on `127.0.0.1`, real TUN (`rbtc0` / `rbtc1`) | Silent bind to `127.0.0.1` if TUN fails |

Tor SOCKS CONNECT to `127.0.0.1` is unsafe/rejected. Tor journeys are
**onion hidden services** (SOCKS domain CONNECT to `.onion`). Do not “prove
proxy” by CONNECT to loopback.

## Runner

```bash
./scripts/overlay-functional/run.sh
./scripts/overlay-functional/run.sh tor_onion_two_node_v2
./scripts/overlay-functional/run.sh --list
```

`run.sh` enters `nix develop .#overlayFunctional` (same rustc 1.95 pin as
the default flake shell, plus `tor` / `i2pd` / `cjdns` from `flake.lock`).
Then:

1. Start the three private meshes.
2. `cargo build -p rbitcoin-node`
3. `cargo test -p rbitcoin-test --features overlay --test overlay -- --quiet …`

Timeout **45 minutes** (i2pd tunnel build on a tiny net is the long pole).

### Env (exported by `run.sh`)

| Variable | Meaning |
|----------|---------|
| `OVERLAY_TOR_SOCKS` | Client SocksPort `host:port` |
| `OVERLAY_TOR_CONTROL` | ControlPort `host:port` |
| `OVERLAY_TOR_COOKIE` | CookieAuthFile path (SAFECOOKIE) |
| `OVERLAY_I2P_SAM` | Node A SAM (`127.0.0.1:port`) |
| `OVERLAY_I2P_SAM_B` | Node B SAM (accept-incoming) |
| `OVERLAY_CJDNS_A` / `OVERLAY_CJDNS_B` | `fc00::/8` IPv6 on each TUN |

### Per-journey walls

| Journey | Wall |
|---------|------|
| Tor HS published (`getnetworkinfo` onion) | ≤ 90s |
| I2P SAM HELLO + STREAM CONNECT | ≤ 180s |
| cjdns TUN TCP | ≤ 60s |

## Journeys (`tests/overlay.rs`)

1. **Tor P2P onion** — B `--listen-onion --tor-control`. A `--proxy socks --only-net onion --connect b.onion --no-listen`. BIP324 v2. A `getpeerinfo.network` is `onion`, not `0.0.0.0`. B has inbound.
2. **Tor wallet HS** — B Electrum + Esplora with `--electrum-onion` and `--esplora-onion`: `ADD_ONION`. Client SOCKS domain CONNECT to `.onion`. Pin `server.features.hosts` and one Esplora REST GET.
3. **I2P SAM** — A/B `--i2p-sam --only-net i2p`; B `--i2p-accept-incoming`. B's `getnetworkinfo` address is the `.b32.i2p:0` hash of the public Destination in `p2p.priv` (not a private re-encode of the whole key file). A STREAM CONNECTs to that name. `getpeerinfo` is `i2p` / v2 and has received `addrv2`.
4. **CJDNS TUN** — A/B `--cjdns-reachable` on real `fc00::/8`. `getpeerinfo.network=cjdns` on both sides. `getnetworkinfo.localaddresses` lists each TUN address without `--external-ip`. TUN create failure is a hard fail.
5. **Ephemeral broadcast** — A `--proxy` (real Tor SOCKS); standing onion peer to B; `sendrawtransaction`; standing session must not INV that tx; a one-shot circuit delivers `tx`.

Out of this harness: seqsigwit prune; public overlays; replacing NixOS
module dummy `tor`/`i2pd` units ([`nixos-module-runtime`](../nix/tests/nixos-module-runtime.nix)
stays argv / `After=` only).

## CI

[`.github/workflows/overlay-functional.yml`](../.github/workflows/overlay-functional.yml):
nightly `42 6 * * *`, `workflow_dispatch`, label **`overlay-functional`**,
label **`release`**, or ship version. Ship and `release` runs come from
[`release-gate.yml`](../.github/workflows/release-gate.yml) (`workflow_call`), and `release-extra` fails a ship PR
unless this job is green. Not required on other PRs.

Unlabeled non-ship PRs stay cargo-only ([`TESTING.md`](../TESTING.md)).
The job needs a TUN plus Tor, i2pd, and cjdns and is capped at 45 minutes,
so it does not run beside the Windows and macOS jobs on every pull request.
The every-PR pin for these flags is `overlay_config` in `rbitcoin-node` and
`rbitcoin-net`. Label harness PRs and ship version-bump PRs. Reproduce locally with `run.sh`
until that script passes; do not push-and-wait on the job as the inner loop.

```bash
./scripts/overlay-functional/run.sh.test.sh
./scripts/overlay-functional/run.sh --list
```
