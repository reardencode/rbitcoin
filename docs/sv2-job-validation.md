# Stratum V2: Custom Job Validation over the Template Distribution Protocol

Draft for [sv2-spec discussion #239](https://github.com/stratum-mining/sv2-spec/discussions/239)
(`ProposeTemplate`, plebhash, 2026-10-06), which supersedes
[sv2-spec#217](https://github.com/stratum-mining/sv2-spec/issues/217), where
this started. Written as new core Template Distribution Protocol (TDP) messages so it can be
folded into `07-Template-Distribution-Protocol.md` and `08-Message-Types.md`.
Section 6 lists the open questions, including the extension alternative.

Terms like "MUST," "MUST NOT," "REQUIRED," etc., follow RFC2119 standards.

## 0. Abstract

Under Full-Template mode a Job Declarator Server (JDS) has to check that a
Custom Job declared by a Job Declarator Client (JDC) would produce a valid
block, and later propagate the block when JDC sends `PushSolution`. The
specification leaves how JDS talks to its Bitcoin node undefined ("RPCs (or
similar)", Section 6.1).

This document adds five TDP messages and one `SetupConnection` flag so that a
JDS can validate a declared Custom Job, and later submit its solution, through
any Template Provider (TP) over the authenticated TDP connection it already
uses. The request carries the subset of `DeclareMiningJob` a node needs,
relayed unchanged; the missing-transactions leg reuses the Job Declaration
Protocol's own `ProvideMissingTransactions` pair, relayed unchanged in both
directions. The exchange mirrors the flow the Job Declaration Protocol
already imposes on JDS: look transactions up by `wtxid`, ask JDC for the ones
nobody has, validate, and submit the solution by reference.

## 1. Motivation

- Section 6.1 names the JDS-to-node link but does not specify it. The
  reference implementation (`sv2-apps`) validates Custom Jobs only through
  Bitcoin Core's multiprocess IPC mining interface (`checkBlock`,
  `getTransactionsByWitnessID`). A Pool configured with a standalone TP
  (`Sv2Tp`) refuses to run a JDS. Nodes that are not Bitcoin Core, and Bitcoin
  Core nodes on another host, cannot back a JDS today.
- An earlier JSON-RPC JDS backend (`getrawmempool` polling, `getrawtransaction`,
  `submitblock`) was removed in `sv2-apps#299` because of polling cost and
  lock contention. A push-based, binary, authenticated channel already exists
  between JDS and TP: TDP.
- The Bitcoin Core and SRI developers have converged on a node-side flow for
  this problem (`TxCollection`, bitcoin/bitcoin#35671, discussed in
  `sv2-apps#609`): collect transactions by `wtxid`, report the unknown ones,
  add the missing ones, validate, then submit the solution by reference
  without resending the block. This proposal is that flow expressed as TDP
  messages, so `sv2-tp` can serve it on top of Core IPC, and a node with a
  native TP can serve it directly.
- Validation by `wtxid` position lets JDS relay the TP's
  `ProvideMissingTransactions` to JDC and JDC's
  `ProvideMissingTransactions.Success` to the TP byte for byte, as Sections
  6.4.7 and 6.4.8 already require of it; only the message type changes.

## 2. Overview

```
JDC                      JDS                             TP
 |-- DeclareMiningJob --->|                               |
 |                        |-- ProposeTemplate --------->|  version, coinbase prefix/suffix, wtxid_list; no txs
 |                        |<- ProvideMissingTransactions |  only if the TP lacks some; the TP holds the proposal
 |<- ProvideMissingTransactions           |               |  same payload, JDP message type
 |-- ProvideMissingTransactions.Success ->|               |
 |                        |-- ProvideMissingTransactions.Success ->|  same payload, TDP message type
 |                        |<- ProposeTemplate.Success --|  request_id, template_id, prev_hash, fees
 |<- DeclareMiningJob.Success             |               |
 ...
 |-- PushSolution ------->|                               |
 |                        |-- SubmitSolution(template_id)>|  existing 7.8 message
```

- The TP holds a proposal it answered `ProvideMissingTransactions` under
  its `request_id` until the `ProvideMissingTransactions.Success` arrives
  or a timeout passes (Section 4.1). `request_id` pairs the whole exchange,
  as it pairs `DeclareMiningJob` with its `ProvideMissingTransactions` in
  Section 6.4.7. The JDS relays the two provide messages without parsing
  them.
- `ProposeTemplate` carries no `prev_hash`: `DeclareMiningJob` has none, so a
  JDS cannot supply one without guessing. The TP validates against its own
  current tip and names that tip in `ProposeTemplate.Success.prev_hash`, which
  the JDS keeps to check `PushSolution.prev_hash` against.
- `ProposeTemplate.Success` assigns a `template_id` from the same namespace as
  `NewTemplate.template_id`. The solution is then sent with the existing
  `SubmitSolution` message (Section 7.8). No new submission message is needed.
- A JDS connection is an ordinary TDP client. It MUST still open with
  `CoinbaseOutputConstraints` (Section 7.2) and will receive `NewTemplate` and
  `SetNewPrevHash` messages, which it MAY ignore or use to prefetch
  transaction data for its own cache.

## 3. `SetupConnection` Flags for Template Distribution Protocol

Replaces the text of Section 7.1 ("No flags are yet defined").

Flags usable in `SetupConnection.flags` and `SetupConnection.Error.flags`
(Client -> Server):

| Field Name              | Bit | Description                                                                                                                                 |
| ----------------------- | --- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| REQUIRES_JOB_VALIDATION | 0   | The client intends to send `ProposeTemplate`. A server that does not support it MUST reply `SetupConnection.Error` with `unsupported-feature-flags`. |

Flags in `SetupConnection.Success.flags` (Server -> Client):

| Field Name              | Bit | Description                                                                 |
| ----------------------- | --- | --------------------------------------------------------------------------- |
| REQUIRES_JOB_VALIDATION | 0   | Set when the server accepted the client's `REQUIRES_JOB_VALIDATION` request |

A client MUST NOT send `ProposeTemplate` on a connection where this flag was
not set and accepted.

## 4. Messages

### 4.1 `ProposeTemplate` (Client -> Server)

Asks the Template Provider whether a Custom Job, declared to the client via
`DeclareMiningJob`, would produce a consensus-valid block on top of the
server's current chain tip.

| Field Name         | Data Type        | Description                                                                                                                                                                                                                                                                              |
| ------------------ | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| request_id         | U32              | Unique identifier for pairing the response                                                                                                                                                                                                                                               |
| version            | U32              | Block header version field as declared in `DeclareMiningJob.version`. BIP323 general-purpose bits are ignored by the server                                                                                                                                                              |
| coinbase_tx_prefix | B0_64K           | `DeclareMiningJob.coinbase_tx_prefix` unchanged: the serialized coinbase up to and including the scriptSig bytes before the extranonce                                                                                                                                                   |
| coinbase_tx_suffix | B0_64K           | `DeclareMiningJob.coinbase_tx_suffix` unchanged: the serialized coinbase from the input's `nSequence` on. If the coinbase is a SegWit transaction, BIP141 fields (marker and flag in the prefix; witness count, witness length, witness reserved value in the suffix) MUST NOT be stripped |
| wtxid_list         | SEQ0_64K[U256]   | `wtxid` of every transaction in the Custom Job, in block order, excluding the coinbase. Copied from `DeclareMiningJob.wtxid_list`                                                                                                                                                         |
| excess_data        | B0_64K           | `DeclareMiningJob.excess_data` unchanged. Opaque to the server; its meaning is between JDC and Pool (Section 7.6)                                                                                                                                                                         |

The server reconstructs a placeholder coinbase as `coinbase_tx_prefix` ||
`E` zero bytes || `coinbase_tx_suffix`, where `E` is the scriptSig length
the prefix encodes minus the scriptSig bytes the prefix carries: parse the
version (4 bytes), the BIP144 marker `0x00` and flag `0x01` when present, the
input count (MUST be 1), the 36-byte prevout, and the scriptSig length `L` as
a CompactSize, leaving `P` bytes; `E = L - P`. The server MUST require
`2 <= L <= 100` and `P <= L`, and MUST reply `bad-cb-decode` when the prefix
does not parse this way or the reconstructed bytes do not decode as a
transaction. This assumes the extranonce is the final part of the scriptSig,
so `coinbase_tx_suffix` begins at `nSequence`. That is how
`NewExtendedMiningJob` splits the coinbase in practice and what the reference
JDS already assumes, but the Job Declaration Protocol does not state it; see
Section 6. The placeholder value is irrelevant: the server does not check the
merkle root or proof of work, and every other coinbase check (size, weight,
BIP34 height push, output values, witness commitment) is independent of the
extranonce bytes.

The server resolves each `wtxid` against its mempool. If any transaction is
unknown, it MUST reply `ProvideMissingTransactions` (Section 4.2) and hold
the proposal under its `request_id`: it MUST keep the proposal available for
a `ProvideMissingTransactions.Success` (Section 4.3) for at least N seconds
(RECOMMENDED 30) and MAY bound the proposals held per connection, dropping
the oldest. A `ProvideMissingTransactions.Success` for a `request_id` the
server does not hold, no longer holds, or has already consumed is answered
`ProposeTemplate.Error` with `unknown-request-id`; a `ProposeTemplate` whose
`request_id` the server has accepted and not yet answered, or still holds,
is answered `duplicate-request-id`.
Once every transaction is known, from the mempool or the provide, the server
MUST validate the job as a block on top of its current chain tip with the
following rules, and reply either `ProposeTemplate.Success` or
`ProposeTemplate.Error`:

- The server validates against its own current tip and reports that tip in
  `ProposeTemplate.Success.prev_hash`. There is no stale-tip error code: a
  job declared for a tip the server has since left fails the checks below on
  its own, normally the BIP34 height push (`bad-cb-height`) or an input the
  new tip spent; a job that still passes on the new tip is valid there.
- `wtxid_list` MUST contain no duplicates (`duplicate-wtxid`), and every
  entry of `ProvideMissingTransactions.Success.transaction_list` MUST hash to
  a `wtxid` at a position the server asked for (`bad-missing-tx`). Both
  checks MUST run before any transaction is decoded or copied.
- The server MUST apply every consensus check it would apply to a received
  block except the proof-of-work check and the merkle-root check. This
  includes: transaction validity and input availability against the UTXO set
  and the mempool, transaction ordering, block weight and sigop limits with
  the reconstructed coinbase counted, coinbase scriptSig length and BIP34
  height, coinbase output value not exceeding subsidy plus fees, and the
  BIP141 witness commitment computed over `wtxid_list` with the witness
  reserved value taken from `coinbase_tx_suffix`. This is the check performed by
  `getblocktemplate` in `proposal` mode and by Bitcoin Core's IPC
  `checkBlock` with `checkMerkleRoot=false` and `checkPow=false`.
- The server MUST NOT reject a consensus-valid job on local policy grounds
  (standardness, minimum relay fee, mempool limits). Policy belongs to the
  Pool, which prices the declared coinbase from the coinbase itself.
- The server MUST set `nBits` from its own view of the chain and MAY use its
  current time for `nTime` when it needs a header for contextual checks. The
  client does not supply them.

### 4.2 `ProvideMissingTransactions` (Server -> Client)

The server does not know some of the transactions in `wtxid_list` and holds
the proposal. The field layout is `ProvideMissingTransactions` of Section
6.4.7 of the Job Declaration Protocol under a TDP message type, so the
client copies the payload to JDC as its own `ProvideMissingTransactions`.

| Field Name               | Data Type     | Description                                                                                                                      |
| ------------------------ | ------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| request_id               | U32           | Identifier of the original `ProposeTemplate` request                                                                             |
| unknown_tx_position_list | SEQ0_64K[U16] | Positions in `wtxid_list` of the transactions the server lacks, 0-indexed, not including the coinbase. As in Section 6.4.7      |

The positions are relative to `wtxid_list`, which is a copy of
`DeclareMiningJob.wtxid_list`, so they are JDC's positions too.

A server MAY answer a `ProvideMissingTransactions.Success` with another
`ProvideMissingTransactions`, for example when a transaction left its
mempool between the two. A server that holds no transactions across the
round trip then names every position it still lacks, the ones already
supplied included. A client SHOULD bound how many times it retries one
declaration.

### 4.3 `ProvideMissingTransactions.Success` (Client -> Server)

The transactions a `ProvideMissingTransactions` asked for. The field layout
is `ProvideMissingTransactions.Success` of Section 6.4.8, so the client
copies JDC's payload under the TDP message type.

| Field Name       | Data Type        | Description                                                                                                                                                                  |
| ---------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| request_id       | U32              | Identifier of the original `ProposeTemplate` request                                                                                                                         |
| transaction_list | SEQ0_64K[B0_16M] | The transactions at the requested positions, in the order they were requested. Each MUST be relayed exactly as received from JDC, without parsing or re-encoding             |

The server MUST check that every entry hashes to a requested `wtxid` and
that every requested position is covered, before decoding any of them: a
provide that is short, carries a transaction nobody asked for, or carries
one that does not decode is `ProposeTemplate.Error` with `bad-missing-tx`.
Otherwise the server completes the validation of Section 4.1 with the
supplied transactions merged in and replies `ProposeTemplate.Success` or
`ProposeTemplate.Error`. The proposal is no longer held either way; a second
`ProvideMissingTransactions.Success` for the same `request_id` is
`unknown-request-id`.

### 4.4 `ProposeTemplate.Success` (Server -> Client)

The job is consensus-valid on the server's current tip. The server has stored
the job and will accept a `SubmitSolution` for it.

| Field Name  | Data Type | Description                                                                                                                                                                            |
| ----------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| request_id  | U32       | Identifier of the original `ProposeTemplate` request                                                                                                                                  |
| template_id | U64       | Server's identification of the validated job. Drawn from the same strictly increasing namespace as `NewTemplate.template_id`, so it can be used in `SubmitSolution` and `RequestTransactionData` |
| prev_hash   | U256      | Hash of the server's chain tip the job was validated on, as it would appear in the block header. The client keeps it to compare against `PushSolution.prev_hash`                      |
| fees        | U64       | Sum of the fees of the transactions in `wtxid_list`, in satoshis, as computed by the server's validation                                                                               |

The server MUST retain the validated job (its transactions in block order
and the header fields a `SubmitSolution` is assembled with) under the same
rules as its own templates: it is retired after the stale grace that follows
a tip change, and it MAY be evicted oldest-first by a per-connection cap on
retained templates and jobs, which SHOULD be at least 64. A JDS multiplexes
many JDCs over one connection, so no single job is "the latest"; a
`SubmitSolution` for an id the server no longer retains is dropped (Section
7.8 has no reply) and `RequestTransactionData` for it answers
`stale-template-id` or `template-id-not-found`. See Section 7.1 for what the
JDS does with that.

### 4.5 `ProposeTemplate.Error` (Server -> Client)

The job was not validated. The client decides what to tell JDC; it SHOULD map
consensus rejections to `DeclareMiningJob.Error` and SHOULD NOT treat the
rejection of a job declared on a tip the server has since left (a
`bad-cb-height` for a job the client knows was built on the previous
`ProposeTemplate.Success.prev_hash`) as a JDC fault.

| Field Name    | Data Type | Description                                            |
| ------------- | --------- | ------------------------------------------------------ |
| request_id    | U32       | Identifier of the original `ProposeTemplate` request   |
| error_code    | STR0_255  | Human-readable error code(s)                           |
| error_details | B0_64K    | Optional data providing further details to given error |

Recommended `error_code` values, in addition to the node's own BIP22-style
rejection strings (`bad-txns-inputs-missingorspent`, `bad-cb-length`,
`bad-witness-merkle-match`, `bad-blk-weight`, and so on):

| error_code                | Meaning                                                              |
| ------------------------- | -------------------------------------------------------------------- |
| duplicate-wtxid           | `wtxid_list` contains the same `wtxid` more than once                |
| bad-missing-tx            | `ProvideMissingTransactions.Success.transaction_list` does not cover every requested position, or an entry does not hash to a requested `wtxid` or does not decode as a transaction |
| unknown-request-id        | `ProvideMissingTransactions.Success.request_id` names no proposal the server holds: never asked about, already answered, dropped under the per-connection bound, or past the hold timeout |
| duplicate-request-id      | `ProposeTemplate.request_id` names a proposal the server has accepted and not yet answered, or still holds for its missing transactions |
| bad-cb-decode             | `coinbase_tx_prefix` does not parse as one input with a scriptSig length covering the bytes present, or the reconstructed coinbase does not decode |
| job-validation-unavailable | The server cannot validate now (for example, initial block download) |

### 4.6 `SubmitSolution` for validated jobs

When the client receives `PushSolution` from JDC it SHOULD check
`PushSolution.prev_hash` against the `ProposeTemplate.Success.prev_hash`
stored with the declaration, then MUST reconstruct the full coinbase
(`coinbase_tx_prefix` || `extranonce` || `coinbase_tx_suffix`) and send
`SubmitSolution` (Section 7.8) with `template_id` set to the value from
`ProposeTemplate.Success`, and `version`, `ntime`, `nonce` and `coinbase_tx`
from the solution.

The server MUST treat such a `SubmitSolution` as it treats one for its own
templates: assemble the block from the retained job and the submitted
coinbase, validate it fully, including proof of work and merkle root, and
attempt to propagate it. `SubmitSolution.ntime` MUST satisfy the `ntime_start`
rule of Section 7.8 relative to the latest `SetNewPrevHash` the server sent on
this connection.

A server MAY also answer `RequestTransactionData` for a validated job's
`template_id`, returning the full transaction set in block order.

## 5. Message Types

Additions to Section 8, Template Distribution Protocol:

| Message Type (8-bit) | channel_msg bit | Message Name                            |
| -------------------- | --------------- | --------------------------------------- |
| 0x77                 | 0               | ProposeTemplate                         |
| 0x78                 | 0               | ProvideMissingTransactions              |
| 0x79                 | 0               | ProposeTemplate.Success                 |
| 0x7a                 | 0               | ProposeTemplate.Error                   |
| 0x7b                 | 0               | ProvideMissingTransactions.Success      |

All five are core messages and carry `extension_type = 0x0000`. The two
`ProvideMissingTransactions` numbers are this draft's proposal; discussion
#239 has agreed on the request/provide shape but assigned no numbers yet.
The names repeat the Job Declaration Protocol's on purpose, as
`SetNewPrevHash` is both 0x20 and 0x72: the payloads are the same.

## 6. Design notes and open questions

- **Core messages or an extension.** Issue 217 proposes a core TDP message.
  The same five messages could instead be extension `0x0003`, negotiated with
  `RequestExtensions` (extension `0x0001`) and framed with
  `extension_type = 0x0003`. The `SetupConnection` flag in Section 3 gives
  negotiation without requiring extension `0x0001` in TPs, which is why the
  draft uses it. The field tables are identical either way.
- **Extranonce position.** The server-side placeholder construction in
  Section 4.1 needs the extranonce to be the tail of the scriptSig. Either
  the Job Declaration Protocol should state that
  `DeclareMiningJob.coinbase_tx_suffix` begins at `nSequence`, or
  `DeclareMiningJob` should carry the extranonce size. The reference JDS has
  the same dependency today when it rebuilds the coinbase for Core's
  `checkBlock` (`sv2-apps#645`).
- **No `prev_hash` in the request.** `DeclareMiningJob` carries none, so a
  JDS would have to guess one; the request would also go stale in flight. The
  server validates on its own tip and names it in `Success` (discussion #239).
  A declaration from before a tip change is caught by the BIP34 height push,
  not by a dedicated code.
- **Coinbase-only mode.** Out of scope. In Coinbase-only mode neither Pool nor
  JDS learns the transaction set, so a node has nothing to validate beyond the
  coinbase, which `SetCustomMiningJob` already carries to the Pool.
- **Node load.** Full block validation without proof of work is CPU-heavy and
  in Bitcoin Core currently serialises on `cs_main`, so validations on a node
  that also produces the Pool's templates can delay block processing
  (`sv2-apps#120`). A server MAY process `ProposeTemplate` requests
  sequentially and MAY bound the number queued per connection; operators
  SHOULD run a dedicated TP for job validation. A client SHOULD apply a
  timeout before falling back. A server SHOULD NOT let a validation delay
  the other messages on the connection, `SubmitSolution` above all
  (rbitcoin validates off the session loop, four at a time per connection,
  the rest queued in arrival order).
- **At the in-flight bound: queue or refuse (open).** A server that runs a
  bounded number of validations at once has two choices for the next
  proposal: rbitcoin queues it in arrival order with no depth cap (four in
  flight per connection), sv2-tp refuses it with
  `job-validation-unavailable`. A JDS should cope with both, a refusal as
  a retry after a backoff and a queue as a longer wait under its own
  timeout, but the thread should settle which the text recommends.
- **Untrusted input.** Everything in `ProposeTemplate` originates from a
  JDC. The server MUST enforce the `duplicate-wtxid` and `bad-missing-tx`
  checks and the block weight limit before decoding or storing transactions,
  so that a 32-byte `wtxid` cannot be amplified into a large allocation
  (`sv2-apps#796`, `#795`).
- **Why `fees` is in `Success`.** The fee total (sum of inputs minus sum of
  outputs per transaction) needs the UTXO set, so only the validating node
  can derive it, and it computes it anyway for `bad-cb-amount`. Without it
  the Pool has only the value the coinbase claims, which that check makes a
  lower bound on the real total, not the total (`sv2-apps#610`). Bitcoin
  Core's IPC does not expose it today: `checkBlock` returns only a reason, a
  debug string and a result, and a template from `TxCollection.makeTemplate`
  throws on `getTxFees`. That gap is raised on bitcoin/bitcoin#35671 rather
  than designed around.
- **`template_id` is per connection.** `ProposeTemplate.Success.template_id`
  MUST be unique within a connection and MUST NOT collide with a
  `NewTemplate.template_id` sent on it. The server MAY draw it from a
  per-connection counter (rbitcoin) or a server-global one (`sv2-tp`); a
  client MUST NOT compare ids across connections.
- **Why the TP holds state.** An earlier draft repeated the whole
  `ProposeTemplate` with a `transaction_list`, so the TP needed nothing
  between the two requests. Sjors (#239, 2026-10-08) asked for the missing
  leg to be proper request and provide messages, conceptually the existing
  ones, which is also how `TxCollection` works in Bitcoin Core: `collectTxs`
  returns the handle whose `unknownTxPos` the TP reports and whose
  `addMissingTxs` the provide feeds, so the handle is the held proposal. A
  held proposal costs its `wtxid_list` and coinbase split, not transactions,
  so a bounded table per connection is enough (rbitcoin: 8 proposals, 30 s).
  A dropped or expired hold surfaces as `unknown-request-id` and the JDS
  proposes again; that is the one recovery path.
- **Why positions, not `wtxid`s, in `ProvideMissingTransactions`.** Section
  6.4.7 uses positions, so the JDS relays the list unchanged. A `wtxid` list
  would force the JDS to translate.
- **Why no separate `SubmitBlock`.** The server already holds the validated
  transaction set; resending up to 4 MB at block-find time only adds latency.
  Reusing `SubmitSolution` is also what `TxCollection.makeTemplate` followed by
  `BlockTemplate.submitSolution` does in Bitcoin Core.

## 7. Implementation notes

### 7.1 JDS

| JDP event                            | TDP action                                                                    |
| ------------------------------------ | ----------------------------------------------------------------------------- |
| `DeclareMiningJob`                   | `ProposeTemplate` with `version`, `coinbase_tx_prefix`, `coinbase_tx_suffix`, `wtxid_list`, `excess_data` copied unchanged |
| `ProvideMissingTransactions` (from the TP) | `ProvideMissingTransactions` to JDC: the payload copied, the JDP message type |
| `ProvideMissingTransactions.Success` (from JDC) | `ProvideMissingTransactions.Success` to the TP: the payload copied, the TDP message type |
| `ProposeTemplate.Success`          | `DeclareMiningJob.Success`; store `template_id` and `prev_hash` with the declaration; pass `fees` to the Pool, which prices the declared coinbase against it |
| `ProposeTemplate.Error`            | `DeclareMiningJob.Error` with the error code; on `unknown-request-id` after a slow JDC, a new `ProposeTemplate` instead |
| `PushSolution`                       | Check `prev_hash` against the stored one, then `SubmitSolution(template_id, version, ntime, nonce, coinbase_tx)` |

Solutions are keyed by `template_id`. When the server has already dropped
the job (Section 4.3), the `SubmitSolution` is lost silently; the JDS needs no
fallback, because Section 6.4.9 already has JDC propagate the block itself and
the JDS submission is redundancy.

No mempool mirror is needed on the JDS side. In `sv2-apps` this is a second
`JobValidationEngine` implementation next to `BitcoinCoreIPCEngine`, and the
Pool's "`[jds]` requires `BitcoinCoreIpc`" startup check becomes "requires
`BitcoinCoreIpc` or a TP that accepted `REQUIRES_JOB_VALIDATION`".

### 7.2 Template Provider on Bitcoin Core (`sv2-tp`)

`ProposeTemplate` maps onto `getTransactionsByWitnessID` (Core v32) for the
lookup and `checkBlock(checkMerkleRoot=false, checkPow=false)` for validation,
or onto `TxCollection` (`collectTxs`, `unknownTxPos`, `addMissingTxs`,
`makeTemplate`) once bitcoin/bitcoin#35671 lands; the held proposal of
Section 4.1 is then the `TxCollection` handle itself. `SubmitSolution` for a
validated job maps onto `submitBlock` or `BlockTemplate.submitSolution`.

### 7.3 Template Provider in a node

A node with a native TP serves this from its own mempool lookup, block
assembler and block acceptance path. For rbitcoin that is `rbitcoin-sv2` plus
the `getblocktemplate` proposal check and the `submitblock` path, with no new
dependency.

## 8. Prior art

- [sv2-spec discussion #239](https://github.com/stratum-mining/sv2-spec/discussions/239):
  "RFC: `ProposeTemplate`" (plebhash, 2026-10-06), supersedes #217. Names the
  message and carries the subset of `DeclareMiningJob` a node needs
  (`request_id`, `version`, `coinbase_tx_prefix`, `coinbase_tx_suffix`,
  `wtxid_list`, `excess_data`), with no `prev_hash`. Sjors (2026-10-08)
  asked for the missing leg to be proper request and provide messages
  reusing the existing ones, mandatory `template_id`, and no second flag.
  This draft follows both: the `ProvideMissingTransactions` pair under TDP
  numbers, and `prev_hash` and `fees` in `Success`.
- [sv2-spec#217](https://github.com/stratum-mining/sv2-spec/issues/217):
  "consider adding a new TDP message for custom job validation" (plebhash,
  2026-08-31). Proposes message `X`, `X.Error` triggering
  `ProvideMissingTransactions`, `X.Success` gating `DeclareMiningJob.Success`,
  and asks whether Coinbase-only mode could use it. Where this draft started.
- [sv2-spec#170](https://github.com/stratum-mining/sv2-spec/issues/170)
  (closed): `DeclareMiningJob` moved from `txid` to `wtxid` so JDS cannot match
  a transaction with a different witness. Names `getblocktemplate` `proposal`
  and Core's `checkBlock()` as the two ways JDS checks a block.
- [sv2-apps#120](https://github.com/stratum-mining/sv2-apps/issues/120)
  (closed by #299): the thread where `checkBlock()` was chosen as the JDS
  validation tool. Sjors: `checkBlock()` holds `cs_main`, so calls serialise
  and should not run on the node that produces default templates. Also
  records that `libbitcoinkernel` was considered and rejected.
- [sv2-apps#268](https://github.com/stratum-mining/sv2-apps/issues/268) and
  [bitcoin/bitcoin#34020](https://github.com/bitcoin/bitcoin/pull/34020)
  (merged 2026-07-07, Core v32): `getTransactionsByWitnessID`, lookup by
  `wtxid` with empty slots for unknown transactions.
- [sv2-apps#609](https://github.com/stratum-mining/sv2-apps/issues/609) and
  [bitcoin/bitcoin#35671](https://github.com/bitcoin/bitcoin/pull/35671)
  (open): `TxCollection`. The combined flow written up there (collect by
  `wtxid`, report unknown positions, add missing, `makeTemplate`, submit the
  solution by reference) is the flow Sections 2 and 4 encode. The handle
  `collectTxs` returns is the state a TP holds across the round trip; this
  draft bounds that state per connection (Section 4.1) instead of avoiding
  it.
- [sv2-apps#299](https://github.com/stratum-mining/sv2-apps/pull/299): JDS
  refactor that removed the JSON-RPC backend and folded JDS into the Pool.
  [sv2-apps#26](https://github.com/stratum-mining/sv2-apps/issues/26) gives the
  reasons: per-second RPC polling and lock contention.
- [sv2-apps#597](https://github.com/stratum-mining/sv2-apps/issues/597),
  [#610](https://github.com/stratum-mining/sv2-apps/issues/610),
  [#645](https://github.com/stratum-mining/sv2-apps/issues/645),
  [#795](https://github.com/stratum-mining/sv2-apps/issues/795),
  [#796](https://github.com/stratum-mining/sv2-apps/issues/796): JDS
  hardening issues that shaped Section 4.1's rules (stale detection, payout
  versus fees, coinbase prefix reconstruction, staging supplied
  transactions, duplicate `wtxid` amplification).
- `06-Job-Declaration-Protocol.md` Section 6.1 ("RPCs (or similar)") and
  Sections 6.4.7 to 6.4.9, whose encodings this draft copies.
