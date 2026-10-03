# 084 — Empty sig in legacy CHECKMULTISIG did not delete OP_0

**Severity:** critical
**Status:** fixed
**Found by:** script flag parity review, 2026-10-02

Base (pre-segwit) `CHECKMULTISIG` runs `FindAndDelete(scriptCode,
CScript() << vchSig)` for every signature before the key walk. For an
empty signature, `CScript() << vchSig` is the one-byte push `0x00`, so
Core removes every `OP_0` opcode from scriptCode. Our `find_and_delete`
returned the script unchanged for empty data.

The other signatures then hash a different scriptCode. The verdict is
still false for the op itself (an empty signature never matches), but
whether a non-empty signature matches decides how far the key walk
goes, and DERSIG runs on each signature the walk reaches.

Example output script `OP_0 OP_DROP 3 <k1> <k2> <k3> 3 CHECKMULTISIG NOT`,
scriptSig `OP_0 <empty> <0x01> <sig by k3>`:

| `sig by k3` signs | Core | rbitcoin before |
|-------------------|------|-----------------|
| full script | valid (no match, early exit, `NOT`) | invalid (match, walk hits bad DER) |
| script without `OP_0` | invalid (`SIG_DER`) | valid |

Both directions split from Core under consensus flags alone. Both
transactions were checked against libbitcoinconsensus 0.105.0+25.1
(`verify_with_flags`, `VERIFY_ALL` and `P2SH|DERSIG`): first accepted,
second rejected.

A single `CHECKSIG` with an empty signature is false whatever the
scriptCode, so only CHECKMULTISIG is observable. CONST_SCRIPTCODE
(policy) now also rejects a multisig whose empty signature deletes an
`OP_0`, as in Core.

Follow-ups: single-`CHECKSIG` CONST_SCRIPTCODE parity for an empty
signature lands with the policy flag work. `find_and_delete` still
stops at a truncated PUSHDATA header and drops the trailing bytes where
Core copies them; such a script fails at that push either way, so only
the error differs (CONST_SCRIPTCODE).

**Regression:** consensus matrix row C34, `rbitcoin-consensus`
`script::tests_verify::legacy_multisig_empty_sig_deletes_op_0_from_script_code`
