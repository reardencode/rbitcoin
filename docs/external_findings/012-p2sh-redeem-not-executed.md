# P2SH redeemScripts skipped when BIP16 looks inactive

**Component:** `rbitcoin-consensus` (`block::bip16_active_from_prev_mtp`)
**Audit pin:** fuzzamoto report 001 / rbitcoin `8f3990f`
**Severity:** high — consensus accept-invalid
**Status:** fixed — `bip16_from_prev_mtp_exception_and_time` (buried P2SH)
**Found by:** fuzzamoto (Core primary vs rbitcoin)

## Summary

BIP16 is gated on previous-block median-time-past ≥ historical `bip16_time`
(2012-04-01). On regtest (genesis Feb 2011) and any chain whose prev MTP is
still earlier, `bip16_active` is false. P2SH-shaped outputs then take the **bare**
path (`HASH160 EQUAL` only). The redeemScript is **never executed**, so a redeem
with an undefined opcode still “pays.” Core rejects; we accept.

Modern Core buries P2SH: block script flags always include `SCRIPT_VERIFY_P2SH`
except the named per-network exception hash (mainnet **BIP16Exception**,
testnet3 `00000000dd30…b105`). We must match that — not invent
an earlier or later mainnet schedule. Keep the exception (and genesis) off.

## Fix

`bip16_active_from_prev_mtp`: after exception-hash / genesis carve-outs, return
**true** (ignore MTP). Pin exception still false. Red: undefined-opcode redeem
on an early-MTP/regtest chain must reject. Testnet3 exception:
`bip16_testnet3_exception_block`.
