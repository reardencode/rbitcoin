# Stratum V2: Custom Job Validation over the Template Distribution Protocol

Draft for discussion on [sv2-spec#217](https://github.com/stratum-mining/sv2-spec/issues/217).
Written as new core Template Distribution Protocol (TDP) messages so it can be
folded into `07-Template-Distribution-Protocol.md` and `08-Message-Types.md`.
Section 6 lists the open questions, including the extension alternative.

Terms like "MUST," "MUST NOT," "REQUIRED," etc., follow RFC2119 standards.

## 0. Abstract

Under Full-Template mode a Job Declarator Server (JDS) has to check that a
Custom Job declared by a Job Declarator Client (JDC) would produce a valid
block, and later propagate the block when JDC sends `PushSolution`. The
specification leaves how JDS talks to its Bitcoin node undefined ("RPCs (or
similar)", Section 6.1).

This document adds four TDP messages and one `SetupConnection` flag so that a
JDS can validate a declared Custom Job, and later submit its solution, through
any Template Provider (TP) over the authenticated TDP connection it already
uses. The exchange mirrors the flow the Job Declaration Protocol already
imposes on JDS: look transactions up by `wtxid`, ask JDC for the ones nobody
has, validate, and submit the solution by reference.

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
- Validation by `wtxid` position lets JDS relay `ProvideMissingTransactions`
  and `ProvideMissingTransactions.Success` payloads between JDC and TP without
  parsing them, as Sections 6.4.7 and 6.4.8 already require.

## 2. Overview

```
JDC                      JDS                             TP
 |-- DeclareMiningJob --->|                               |
 |                        |-- ProposeTemplate --------->|  wtxid_list, coinbase, no txs
 |                        |<- ProposeTemplate.MissingTransactions   (only if TP lacks some)
 |<- ProvideMissingTransactions                           |
 |-- ProvideMissingTransactions.Success ->|               |
 |                        |-- ProposeTemplate --------->|  same job + transaction_list
 |                        |<- ProposeTemplate.Success --|  template_id, fees
 |<- DeclareMiningJob.Success             |               |
 ...
 |-- PushSolution ------->|                               |
 |                        |-- SubmitSolution(template_id)>|  existing 7.8 message
```

- `ProposeTemplate` is stateless on the server side across the
  missing-transactions round trip: the second request repeats the job and adds
  the transactions. The TP MUST NOT require any state from the first request.
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

| Field Name       | Data Type        | Description                                                                                                                                                                                                                                                                              |
| ---------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| request_id       | U32              | Unique identifier for pairing the response                                                                                                                                                                                                                                               |
| prev_hash        | U256             | Hash of the block the Custom Job builds on, as it would appear in the block header                                                                                                                                                                                                      |
| version          | U32              | Block header version field as declared in `DeclareMiningJob.version`. BIP323 general-purpose bits are ignored by the server                                                                                                                                                              |
| coinbase_tx      | B0_64K           | Full serialized coinbase transaction, with the extranonce region filled with placeholder bytes of the correct length. If the coinbase is a SegWit transaction, BIP141 fields (marker, flag, witness count, witness length, witness reserved value) MUST NOT be stripped                 |
| wtxid_list       | SEQ0_64K[U256]   | `wtxid` of every transaction in the Custom Job, in block order, excluding the coinbase. Copied from `DeclareMiningJob.wtxid_list`                                                                                                                                                         |
| transaction_list | SEQ0_64K[B0_16M] | Full transactions the server reported in `ProposeTemplate.MissingTransactions`, in the order they were requested. Empty on the first request. Each transaction MUST be relayed exactly as received from JDC in `ProvideMissingTransactions.Success`, without parsing or re-encoding    |

The client derives the extranonce length as the scriptSig length encoded in
`DeclareMiningJob.coinbase_tx_prefix` minus the scriptSig bytes present in the
prefix. This assumes the extranonce is the final part of the scriptSig, so
`coinbase_tx_suffix` begins at `nSequence`. That is how `NewExtendedMiningJob`
splits the coinbase in practice and what the reference JDS already assumes,
but the Job Declaration Protocol does not state it; see Section 6. The
placeholder value is irrelevant: the server does not
check the merkle root or proof of work, and every other coinbase check (size,
weight, BIP34 height push, output values, witness commitment) is independent
of the extranonce bytes.

The server resolves each `wtxid` against its mempool and against
`transaction_list`. If any transaction is still unknown, it MUST reply
`ProposeTemplate.MissingTransactions`. Otherwise it MUST validate the job as
a block on top of `prev_hash` with the following rules, and reply either
`ProposeTemplate.Success` or `ProposeTemplate.Error`:

- `prev_hash` MUST equal the server's current chain tip. Otherwise the server
  MUST reply with error code `stale-prevhash`. The server MUST NOT accept a
  job on a tip it has already left.
- `wtxid_list` MUST contain no duplicates, and every entry of
  `transaction_list` MUST hash to a `wtxid` that the server reported missing.
  Otherwise reply `duplicate-wtxid` or `bad-missing-tx`. These checks MUST run
  before any transaction is decoded or copied.
- The server MUST apply every consensus check it would apply to a received
  block except the proof-of-work check and the merkle-root check. This
  includes: transaction validity and input availability against the UTXO set
  and the mempool, transaction ordering, block weight and sigop limits with
  `coinbase_tx` counted as sent, coinbase scriptSig length and BIP34 height,
  coinbase output value not exceeding subsidy plus fees, and the BIP141
  witness commitment computed over `wtxid_list` with the witness reserved
  value taken from `coinbase_tx`. This is the check performed by
  `getblocktemplate` in `proposal` mode and by Bitcoin Core's IPC
  `checkBlock` with `checkMerkleRoot=false` and `checkPow=false`.
- The server MUST NOT reject a consensus-valid job on local policy grounds
  (standardness, minimum relay fee, mempool limits). Policy belongs to the
  Pool, which can use `ProposeTemplate.Success.fees` for it.
- The server MUST set `nBits` from its own view of the chain and MAY use its
  current time for `nTime` when it needs a header for contextual checks. The
  client does not supply them.

### 4.2 `ProposeTemplate.MissingTransactions` (Server -> Client)

The server does not know some of the transactions in `wtxid_list`. The client
is expected to obtain them from JDC via `ProvideMissingTransactions` and send
a new `ProposeTemplate` with `transaction_list` filled.

| Field Name               | Data Type     | Description                                                                                                                                                    |
| ------------------------ | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| request_id               | U32           | Identifier of the original `ProposeTemplate` request                                                                                                           |
| unknown_tx_position_list | SEQ0_64K[U16] | Positions in `wtxid_list` of the transactions the server lacks, 0-indexed, not including the coinbase. Same encoding as `ProvideMissingTransactions.unknown_tx_position_list` |

The positions are relative to `wtxid_list`, which is a copy of
`DeclareMiningJob.wtxid_list`, so the client can copy this field into
`ProvideMissingTransactions.unknown_tx_position_list` unchanged, and copy
`ProvideMissingTransactions.Success.transaction_list` into
`ProposeTemplate.transaction_list` unchanged.

A server MAY reply `ProposeTemplate.MissingTransactions` to a request whose
`transaction_list` is non-empty, for example when a transaction left its
mempool between the two requests. A client SHOULD bound how many times it
retries one declaration.

### 4.3 `ProposeTemplate.Success` (Server -> Client)

The job is consensus-valid on the server's current tip. The server has stored
the job and will accept a `SubmitSolution` for it.

| Field Name  | Data Type | Description                                                                                                                                                                            |
| ----------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| request_id  | U32       | Identifier of the original `ProposeTemplate` request                                                                                                                                  |
| template_id | U64       | Server's identification of the validated job. Drawn from the same strictly increasing namespace as `NewTemplate.template_id`, so it can be used in `SubmitSolution` and `RequestTransactionData` |
| fees        | U64       | Sum of the fees of the transactions in `wtxid_list`, in satoshis                                                                                                                       |

The server MUST retain the validated job (its `wtxid_list`, the transactions
it received in `transaction_list`, and `coinbase_tx` for size accounting)
until a newer `ProposeTemplate.Success` is sent on the same connection or
the connection closes, whichever comes first. This matches the guarantee JDS
gives JDC in Section 6.4.9: `PushSolution` is only guaranteed to be valid for
the most recent declaration. The server SHOULD retain jobs validated against
the previous tip for a short grace period after a tip change, as it does for
its own templates.

### 4.4 `ProposeTemplate.Error` (Server -> Client)

The job was not validated. The client decides what to tell JDC; it SHOULD map
consensus rejections to `DeclareMiningJob.Error` and SHOULD NOT treat
`stale-prevhash` on a tip the client has not yet seen as a JDC fault.

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
| stale-prevhash            | `prev_hash` is not the server's current tip                           |
| duplicate-wtxid           | `wtxid_list` contains the same `wtxid` more than once                |
| bad-missing-tx            | An entry of `transaction_list` does not hash to a requested `wtxid`  |
| job-validation-unavailable | The server cannot validate now (for example, initial block download) |

### 4.5 `SubmitSolution` for validated jobs

When the client receives `PushSolution` from JDC it MUST reconstruct the full
coinbase (`coinbase_tx_prefix` || `extranonce` || `coinbase_tx_suffix`) and
send `SubmitSolution` (Section 7.8) with `template_id` set to the value from
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
| 0x77                 | 0               | ProposeTemplate                       |
| 0x78                 | 0               | ProposeTemplate.MissingTransactions   |
| 0x79                 | 0               | ProposeTemplate.Success               |
| 0x7a                 | 0               | ProposeTemplate.Error                 |

All four are core messages and carry `extension_type = 0x0000`.

## 6. Design notes and open questions

- **Core messages or an extension.** Issue 217 proposes a core TDP message.
  The same four messages could instead be extension `0x0003`, negotiated with
  `RequestExtensions` (extension `0x0001`) and framed with
  `extension_type = 0x0003`. The `SetupConnection` flag in Section 3 gives
  negotiation without requiring extension `0x0001` in TPs, which is why the
  draft uses it. The field tables are identical either way.
- **Extranonce position.** Section 4.1's placeholder construction needs the
  extranonce to be the tail of the scriptSig. Either the Job Declaration
  Protocol should state that `DeclareMiningJob.coinbase_tx_suffix` begins at
  `nSequence`, or `DeclareMiningJob` should carry the extranonce size. The
  reference JDS has the same dependency today when it rebuilds the coinbase
  for Core's `checkBlock` (`sv2-apps#645`).
- **Coinbase-only mode.** Out of scope. In Coinbase-only mode neither Pool nor
  JDS learns the transaction set, so a node has nothing to validate beyond the
  coinbase, which `SetCustomMiningJob` already carries to the Pool. A
  zero-knowledge extension could later reuse `ProposeTemplate.Success.fees`
  as the quantity being proven.
- **Node load.** Full block validation without proof of work is CPU-heavy and
  in Bitcoin Core currently serialises on `cs_main`, so validations on a node
  that also produces the Pool's templates can delay block processing
  (`sv2-apps#120`). A server MAY process `ProposeTemplate` requests
  sequentially and MAY bound the number queued per connection; operators
  SHOULD run a dedicated TP for job validation. A client SHOULD apply a
  timeout before falling back.
- **Untrusted input.** Everything in `ProposeTemplate` originates from a
  JDC. The server MUST enforce the `duplicate-wtxid` and `bad-missing-tx`
  checks and the block weight limit before decoding or storing transactions,
  so that a 32-byte `wtxid` cannot be amplified into a large allocation
  (`sv2-apps#796`, `#795`).
- **Why `fees` is in `Success`.** The Pool needs the fee revenue of a Custom
  Job to compare the declared coinbase value against what the template is
  worth (`sv2-apps#610`). The server computes it while checking the coinbase
  output value, so returning it costs nothing.
- **Why positions, not `wtxid`s, in `MissingTransactions`.** Section 6.4.7
  uses positions, so the JDS relays the list unchanged. A `wtxid` list would
  force the JDS to translate.
- **Why no separate `SubmitBlock`.** The server already holds the validated
  transaction set; resending up to 4 MB at block-find time only adds latency.
  Reusing `SubmitSolution` is also what `TxCollection.makeTemplate` followed by
  `BlockTemplate.submitSolution` does in Bitcoin Core.

## 7. Implementation notes

### 7.1 JDS

| JDP event                            | TDP action                                                                    |
| ------------------------------------ | ----------------------------------------------------------------------------- |
| `DeclareMiningJob`                   | `ProposeTemplate` with `wtxid_list` copied, `coinbase_tx` from prefix + placeholder + suffix, empty `transaction_list` |
| `ProposeTemplate.MissingTransactions` | `ProvideMissingTransactions` with the position list copied                  |
| `ProvideMissingTransactions.Success` | `ProposeTemplate` again with `transaction_list` copied                       |
| `ProposeTemplate.Success`          | `DeclareMiningJob.Success`; store `template_id` with the declaration           |
| `ProposeTemplate.Error`            | `DeclareMiningJob.Error` with the error code                                  |
| `PushSolution`                       | `SubmitSolution(template_id, version, ntime, nonce, coinbase_tx)`              |

No mempool mirror is needed on the JDS side. In `sv2-apps` this is a second
`JobValidationEngine` implementation next to `BitcoinCoreIPCEngine`, and the
Pool's "`[jds]` requires `BitcoinCoreIpc`" startup check becomes "requires
`BitcoinCoreIpc` or a TP that accepted `REQUIRES_JOB_VALIDATION`".

### 7.2 Template Provider on Bitcoin Core (`sv2-tp`)

`ProposeTemplate` maps onto `getTransactionsByWitnessID` (Core v32) for the
lookup and `checkBlock(checkMerkleRoot=false, checkPow=false)` for validation,
or onto `TxCollection` (`collectTxs`, `unknownTxPos`, `addMissingTxs`,
`makeTemplate`) once bitcoin/bitcoin#35671 lands. `SubmitSolution` for a
validated job maps onto `submitBlock` or `BlockTemplate.submitSolution`.

### 7.3 Template Provider in a node

A node with a native TP serves this from its own mempool lookup, block
assembler and block acceptance path. For rbitcoin that is `rbitcoin-sv2` plus
the `getblocktemplate` proposal check and the `submitblock` path, with no new
dependency.

## 8. Prior art

- [sv2-spec#217](https://github.com/stratum-mining/sv2-spec/issues/217):
  "consider adding a new TDP message for custom job validation" (plebhash,
  2026-08-31, open, no comments). Proposes message `X`, `X.Error` triggering
  `ProvideMissingTransactions`, `X.Success` gating `DeclareMiningJob.Success`,
  and asks whether Coinbase-only mode could use it. This draft is a concrete
  answer to it.
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
  solution by reference) is the flow Sections 2 and 4 encode. The thread also
  records the hazard of server-side state across the missing-transactions
  round trip, which is why `ProposeTemplate` is stateless until `Success`.
- [sv2-apps#299](https://github.com/stratum-mining/sv2-apps/pull/299): JDS
  refactor that removed the JSON-RPC backend and folded JDS into the Pool.
  [sv2-apps#26](https://github.com/stratum-mining/sv2-apps/issues/26) gives the
  reasons: per-second RPC polling and lock contention.
- [sv2-apps#597](https://github.com/stratum-mining/sv2-apps/issues/597),
  [#610](https://github.com/stratum-mining/sv2-apps/issues/610),
  [#645](https://github.com/stratum-mining/sv2-apps/issues/645),
  [#795](https://github.com/stratum-mining/sv2-apps/issues/795),
  [#796](https://github.com/stratum-mining/sv2-apps/issues/796): JDS
  hardening issues that shaped Section 4.1's rules (stale detection by
  `prev_hash` only, payout versus fees, coinbase prefix reconstruction,
  staging supplied transactions, duplicate `wtxid` amplification).
- `06-Job-Declaration-Protocol.md` Section 6.1 ("RPCs (or similar)") and
  Sections 6.4.7 to 6.4.9, whose encodings this draft copies.
