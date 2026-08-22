# Security policy

**rbitcoin** is full-node software intended for **production server-side** use:
IBD and tip follow, block/tx relay, and Electrum serving for **wallet backends**
and similar infrastructure—not a desktop GUI or end-user wallet.

Until **1.0**, treat mainnet deployment as **early production / high-scrutiny**:
on-disk format and APIs can still change (named refuse/wipe, not a silent
wipe), and there is **no** long-term support SLA. **0.5.x** is the supported
published line until 0.6 or 1.0. Run signet first, then mainnet with
monitoring. See [`docs/experimental-mainnet.md`](./docs/experimental-mainnet.md)
and [`OPERATOR.md`](./OPERATOR.md).

## Supported versions

| Version | Support |
|---------|---------|
| **0.5.x** | Supported **published** line. Security-relevant fixes land here until **0.6** or **1.0**. No LTS. Report against the tag (and binary digest if you built musl static). |
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
  (`--maxinbound` / `--maxconnections`, default 125), per-session message/byte
  rate windows, misbehavior score disconnect.
- **Electrum and Esplora (wallet-client backends):** plain TCP/HTTP; TLS is an
  operator reverse-proxy concern. Intended for **wallet software**, not as a
  graphical explorer product. The node is **internet-facing capable**:
  application DoS limits (`ServeLimits` — max connections, request size, idle
  timeout, plus Electrum scripthash-sub / broadcast-hex caps) are **always
  enforced**, not only when bound to localhost. Esplora WebSocket adds a
  **separate** socket cap, inbound frame size limit, and per-connection
  address/tx track caps (defaults 64/64 KiB/64/64). Excess connections and
  oversize lines/bodies/frames fail closed without hanging accept. Esplora is
  opt-in (`--esplora-listen`). Edge TLS, multi-tenant metering, and API keys
  are still out of process (see [`OPERATOR.md`](./OPERATOR.md)).
- **Store / archive:** corruption or incorrect spend/scripthash results that
  mislead a **wallet** backend are in scope.
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

- Callers should assume the usual need for **independent review**, fuzzing, and
  adversarial testing before trusting a deployment with real funds.
- Security reports remain welcome and will be handled through
  [security@reardencode.com](mailto:security@reardencode.com).

## Non-security bugs

Use ordinary issue trackers or contribution channels for non-sensitive crashes,
IBD stalls, and documentation errors — see [`CONTRIBUTING.md`](./CONTRIBUTING.md).
