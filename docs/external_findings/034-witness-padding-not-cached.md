# 034 — Witness padding is not the block hash

**Severity:** high
**Status:** fixed
**Found by:** coordinated review, 2026-09-22 (H-3)

Block weight was checked before the witness commitment. Padding a coinbase
witness past the weight limit failed as `block weight too large` and that
failure was cached on the block hash. Witness bytes are not in the hash, so
the unpadded block was then rejected too.

The unexpected-witness and witness-commitment checks now run first. Both are
mutations (`reject_is_mutated`), shared by connect and the two IBD reject
paths. A weight failure after a matching commitment is still cached: the
commitment is in the coinbase txid, so it is this block.

**Follow-up (2026-10):** the typed IBD confirm path
(`ConfirmRejectClass::from_consensus`) only treated `merkle root mismatch`
as soft, so a witness mutation still blacklisted the hash during IBD. It
now consults `reject_is_mutated` too. Block structure also checks the
merkle root (with the CVE-2012-2459 repeated-tail flag,
`bad-txns-duplicate`) before every other body rule, so a body the header
does not commit to is never blamed on the hash. As in Core's
`MaybePunishNodeForBlock` (`BLOCK_MUTATED`), IBD drops and cools down the
peer that sent the mutated body unless it is noban, so the re-get goes to
another peer.

**Regression:** `rbitcoin-net`
`chain::tests::hostile_peer_session`,
`ibd::events::confirm_reject_tests::ibd_mutated_body_is_refetched_not_blacklisted`
