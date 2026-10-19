# Known btc-lean gaps

Proven rows in the `third_party/btc-lean` census (`spec/db/rules.yaml` at `d390f7932e64a134aec3cca1614bed3276539f2d`) that have no `// btc-lean:` comment. `status: obsolete` is not listed: the vendored status is the reason, and those ids must not be commented. `scripts/btc-lean-census.sh` fails when a proven id is in neither a comment nor this file, or when an id here also has a comment. A gap is not a claim about a Lean theorem.

## MAX_MONEY does not cap an input sum or the block fee

`INV-025` `INV-026` `INV-030` `INV-031` `TXV-023` `TXV-025` `TXV-026` `BLK-091`

Output values and the output sum are capped at MAX_MONEY (`exceeds_max_money` and `money_range_out_sum` in crates/rbitcoin-consensus/src/block/mod.rs). A transaction input sum and the block fee accumulator are not capped at MAX_MONEY. This row is that missing cap, so it has no production site.

## SCRIPT_VERIFY_SIGPUSHONLY is policy

`INV-065` `SCR-010`

SCRIPT_VERIFY_SIGPUSHONLY is a policy flag and is not a field of ScriptVerifyFlags. Consensus P2SH still requires a push-only scriptSig; that is SCR-006 / INV-066, not this policy flag.

## BIP94 is not implemented

`INV-100` `INV-139` `BLK-047` `BLK-055`

BIP94 is not implemented (testnet4 retarget from the first block of the period, and the 600-second timewarp bound). It does not apply to mainnet, testnet3, signet, or default regtest. There is no production check.

## Core Coin is not a type here

`INV-114` `TXV-075` `BLK-101`

Core's Coin type (CTxOut plus height plus coinbase, spent when the out is null) is not a type in this tree. Spends are archive rows resolved in confirm. This row is that C++ data model, not a check we run.

## Core's on-disk Coin word is not our archive layout

`INV-115` `TXV-022`

Core's on-disk Coin word (31-bit height and a coinbase bit in coins.h) is not the rbitcoin archive layout. Height and coinbase-ness are inputs to maturity and BIP30, which are other rows. This row is that Core serialization, which this tree does not use.

## MEMPOOL_HEIGHT is not a value here

`INV-118` `TXV-042`

Core's MEMPOOL_HEIGHT sentinel (a height that is not a block height, used so mempool coins fail BIP68) is not a value in this tree. Mempool inputs are checked against the confirmed tip, not against a fake coin height.

## AssumeUTXO is not implemented

`INV-119`

AssumeUTXO (MuHash of the UTXO set, snapshot hash check) is not implemented.

## CCoinsView best-block pointer

`INV-120`

Core's CCoinsView best-block pointer is not a separate object here. The confirmed tip is the store tip. This row is that coins-view pointer.

## BIP9 state machine is not implemented

`INV-121` `INV-122` `INV-123` `INV-124` `INV-125` `INV-126` `BLK-073` `BLK-074` `BLK-075` `BLK-076` `BLK-077` `BLK-078` `BLK-079` `BLK-080` `SWT-036`

Shipped activations are buried height compares on ChainParams (crates/rbitcoin-consensus/src/params.rs). The BIP9 state machine (STARTED, LOCKED_IN, ACTIVE, FAILED, timeout, threshold) is not implemented. No shipped network still activates a rule through it.

## DeploymentEnabled / DeploymentActiveAt

`INV-138`

Core's DeploymentEnabled / DeploymentActiveAt helpers are not a type here. Activation is ChainParams height predicates plus ScriptVerifyFlags::consensus_at. This row is that C++ API surface, including BIP9 nStartTime, which we do not model.

## assumevalid is not Milestone

`INV-142` `INV-148` `BLK-123`

Core assumevalid is not implemented. That predicate skips scripts only with chain membership, minimum chainwork, and a two-week proof-equivalent-time burial. rbitcoin's script skip is Milestone (crates/rbitcoin-consensus/src/milestone.rs), which is a different rule, so this row is not mapped onto that file.

## CLEANSTACK flag-combination assert

`SCR-009`

CLEANSTACK requiring P2SH and WITNESS is a Core assert on flag combinations. ScriptVerifyFlags does not encode that implication. Witness programs enforce a single-element stack on their own path (interpreter and p2wpkh/p2wsh). This row is the flag-combination assert, which is not a check here.

## WITNESS implies P2SH is an assert

`SCR-014`

Core asserts that the WITNESS flag implies P2SH. ScriptVerifyFlags does not check that combination. Consensus blocks set both through consensus_at except on the BIP16 exception block, which clears both. The assert itself is not a check.

## Mempool sigop standardness cap

`SCR-039`

This row is the mempool standardness cap on sigops per transaction. The consensus block cap is witness_sigops_one and bad-blk-sigops (SCR-038). Mempool admission adjusts vsize from sigops; it does not implement that standardness reject as its own consensus check.

## GetOpName

`SCR-173`

GetOpName is Core's opcode debug string. The interpreter matches opcode bytes and does not publish a name table. The row is not a consensus check.

## Mempool finality calling convention

`TXV-033`

Mempool finality uses the next-block height and the tip's median time, which is node policy context around is_final_tx. The consensus predicate is is_final_tx in crates/rbitcoin-consensus/src/block/mod.rs (INV-011). This row is the mempool calling convention, not a second consensus rule.

## Mempool sequence-lock height

`TXV-041`

Mempool sequence locks are evaluated against tip+1. The consensus predicate is sequence_locks_satisfied in crates/rbitcoin-consensus/src/block/mod.rs. This row is the mempool height convention.

## No flag-epoch mempool rescan

`TXV-061`

Re-checking mempool transactions when consensus flags change at a buried deployment is a mempool maintenance step. Admission uses the same script verifier. There is no separate flag-epoch rescan to cite.

## No wtxid script-execution cache

`TXV-062`

Core's script execution cache keyed by (wtxid, flags) is an equivalence lemma about a cache. rbitcoin does not keep that cache. Script results are not reused across flag sets by a wtxid map.

## MoneyRange on every input fold

`TXV-069`

The row is Core's MoneyRange (0 ≤ x ≤ MAX_MONEY) on each input value, the running input sum, and the fee. Outputs are capped separately. fee_from_values and add_value_in (crates/rbitcoin-consensus/src/block/facts.rs) reject i64 overflow and value-in below value-out, and they do not apply that MoneyRange. The row stays unmapped.

## wtxid mempool identity is relay

`TXV-073`

Using wtxid as the mempool identity (BIP339) is relay, not consensus validity. The wtxid hash itself is tx_precompute.rs (TXV-018).

## No null-header predicate

`BLK-004`

Core's Header::IsNull is nBits == 0. This tree has no null-header predicate. Compact nBits decoding is a different check (BLK-037), so this row is not given a line.

## Witness-validated cache bit

`BLK-127`

Core's fWitnessValidated / witness-cache bits on a block index are not stored. A block is either confirmed or not. This row is that cache flag.

## Coinbase witness reserved value is not invented

`BLK-128`

Core auto-fills an empty coinbase witness with a 32-byte reserved value when a witness commitment is present. rbitcoin requires the reserved value on the wire (witness_commitment checks in crates/rbitcoin-consensus/src/block/mod.rs) and does not invent it. This row is the auto-fill, which we do not do.

## No ScriptExecutionData type

`TPR-072`

ScriptExecutionData is Core's interpreter scratch struct (annex hash, codeseparator position, validation weight). Those fields exist as locals in the interpreter and p2tr paths, but there is no ScriptExecutionData type to cite as this row's owner.

## DeploymentActiveAt(pprev)

`TPR-078`

DeploymentActiveAt(pprev) is Core's 'active in this block if active after the parent' helper. Buried heights are compared directly in ChainParams. The pprev indirection is not a function here.

## Curve and libsecp live in the binding

`SGN-101` `SGN-102` `SGN-103` `SGN-104` `SGN-105` `SGN-106` `SGN-107` `SGN-109` `SGN-110`

The curve, field, and libsecp256k1 parse/verify path are the rust-bitcoin secp256k1 binding, not code in this repository. Signature acceptance is exercised through the script corpora, but this row's Lean proof is about btc-lean's own curve model. There is no local implementation to cite.
