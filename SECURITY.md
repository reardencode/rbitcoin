# Security policy

**rbitcoin** is full-node software intended for **production server-side** use:
IBD and tip follow, block/tx relay, and Electrum serving for **wallet backends**
and similar infrastructure—not a desktop GUI or end-user wallet.

A consensus split on mainnet is vanishingly unlikely. The on-disk format
and APIs can still change before **1.0** (a named refuse or wipe, not a
silent wipe), and there is no long-term support window yet. **1.0** is
where that window, further hardening, and signed release binaries are
planned. In-tree is **0.9.99** (pre-0.10.0). **0.9.x** (tag 0.9.0) is the
published line. **`v0.9.x`** is the patch line.
Occupied **0.6.x** stores refuse
(wipe and sync again). Schema 24 and 25 open in place and rewrite to 26.
A published 0.8 directory is already schema 26. The runbook is
[`docs/operator/mainnet.md`](./docs/operator/mainnet.md). Day-to-day flags
are [`OPERATOR.md`](./OPERATOR.md).

`--trust-peer` stores and serves a chain rbitcoin considers invalid. Do not
point a wallet at that node unless you accept that peer. The fault list is
[`COMPAT.md`](./COMPAT.md).

## Supported versions

| Version | Support |
|---------|---------|
| **0.9.99** (in-tree) | Untagged master toward **0.10.0**. Report against the git commit. |
| **0.9.x** | Published line (0.9.0). No LTS. Report against the tag. |
| **0.8.x** | Previous published line (0.8.0). Report against the tag. |
| **0.7.x** | Previous published line (0.7.0). Report against the tag. |
| **0.6.x** | Previous published line (0.6.0 / 0.6.1). Report against the tag. |
| **0.5.x** | Previous published line (0.5.1 / 0.5.2). Report against the tag. |
| **1.0+** (future) | Will define a clearer support window once the on-disk schema and public surface stabilize. |

Untagged trees: report against a **git commit** (and binary digest if you built musl static).

## Reporting a vulnerability

**Contact:** [security@reardencode.com](mailto:security@reardencode.com)

Report security issues **privately** — do **not** open a public GitHub issue for
unfixed remote, consensus-critical, or data-integrity bugs.

Please include when possible:

1. Affected **commit** (or release tag) and how the binary was built (e.g. musl
   static via `nix build .#rbitcoin-musl`)
2. Network: **mainnet** / **signet** / **regtest**
3. Impact: consensus acceptance/rejection, P2P DoS, Electrum integrity, crash
   under adversarial input, etc.
4. Minimal reproduction (peer behavior, RPC/Electrum request, store fixture)

We aim to acknowledge receipt promptly and to coordinate disclosure for issues
that affect consensus, P2P attack surface, or Electrum/query integrity.

## Scope

- **Consensus and script:** pure-Rust verification; bugs can mean accepting
  invalid chain data or rejecting valid data. Report both.
- **P2P:** BIP324 v2-only. DoS parity with Bitcoin Core is **not** claimed, but
  mitigations are intentional operator surface: max inbound sessions
  (`--max-inbound`, default 200; peers that relay transactions hold at
  most half), per-session message/byte
  rate windows, misbehavior score disconnect. Peer AEAD is the
  `chacha20-poly1305` 0.1 that `bip324` 0.11 links. That is current
  `rust-bitcoin/bip324` master, not a local pin. `noise_sv2` already uses
  the renamed `chacha20poly1305` crate. No version bump until upstream
  publishes one.
- **Electrum and Esplora:** plain TCP/HTTP; TLS is an operator reverse-proxy
  concern. Wallet clients and electrs HTTP (except address-prefix)
  ([`COMPAT.md`](./COMPAT.md)).
  The node is **internet-facing capable**: application DoS limits
  (`ServeLimits` — REST in-flight semaphore, request size, idle timeout, plus
  Electrum scripthash-sub / broadcast-hex caps) are **always enforced**, not
  only when bound to localhost. The REST cap is concurrent requests, not an
  accepted-socket cap. Excess connections and oversize
  lines/bodies fail closed without hanging accept. Esplora is
  opt-in (`--esplora-listen`). Internal electrs HTTP (`/internal/*`) is unix
  listen only, not the public TCP bind. Edge TLS, multi-tenant metering, and API keys
  are still out of process (see [`OPERATOR.md`](./OPERATOR.md)).
- **Health listener:** `--health-listen` is opt-in, read-only, and
  unauthenticated (`/healthz`, `/readyz`, `/progress`, and `/metrics` with
  `--metrics`). It binds before the store opens. Requests carry no body and
  time out; `/readyz` and `/metrics` run a capped number of blocking reads
  and answer 503 past the cap rather than queue. `/progress` is uncapped: it
  reads in-memory counters under one short lock and reveals the bring-up
  phase (as `/readyz` does) and stage names, counts, and timings.
  `/metrics` reveals peer counts and mempool size; keep the port on
  loopback or a probe-only network.
- **Store / archive:** corruption or incorrect spend/scripthash results that
  mislead a **wallet** backend are in scope. Truncating a sealed mmap after
  it is mapped is fatal external corruption (the next read can SIGBUS), not
  a handled retry.
- **No wallet keys in this repository:** do **not** send seed phrases or private
  keys in reports.

## Out of scope (for security@)

- Feature requests, IBD performance, and non-sensitive crashes → ordinary
  issues / [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- Compromised operator hosts, reverse-proxy misconfiguration, or third-party
  wallet software outside this tree

## Authorship and review expectations

**100% of the first-party code in this repository was written by AI** (Grok,
xAI), under the direction and prompting of **Brandon Black**
([@reardencode](https://github.com/reardencode)).

That does **not** change how to report bugs or how seriously we take
consensus/P2P integrity. It **does** mean:

- Independent review and fuzzing continue. A consensus split on mainnet is
  vanishingly unlikely. Further hardening and signed release binaries are
  what 1.0 is for.
- Security reports remain welcome and will be handled through
  [security@reardencode.com](mailto:security@reardencode.com).

## Non-security bugs

Use ordinary issue trackers or contribution channels for non-sensitive crashes,
IBD stalls, and documentation errors — see [`CONTRIBUTING.md`](./CONTRIBUTING.md).
