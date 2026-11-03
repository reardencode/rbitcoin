Fixed

- **RPC amounts print with eight decimals.** `gettxout`,
  `decoderawtransaction`, `getrawtransaction`, `getblock` 2/3, `getpeerinfo`
  `minfeefilter`, `getnetworkinfo` `relayfee` / `incrementalfee` and
  `estimaterawfee` printed values like `50.0`, `0.999998` or `1e-6`. They now
  print Core's fixed eight-decimal number (`50.00000000`, `0.00000100`).
- **RPC asm matches Core.** Every `asm` field (`decodescript`,
  `decoderawtransaction`, verbose `getrawtransaction`, `getblock` 2/3,
  `gettxout`) is Core's `ScriptToAsmStr`: small pushes as numbers, Core
  opcode names, and `[error]` for a truncated push. A scriptSig signature
  that passes Core's strict encoding check ends in its sighash name, such as
  `[ALL]`.
- **`decodescript` returns Core's `p2sh` and `segwit` wraps.** A script Core
  would wrap now gets its P2SH address and a `segwit` object (P2WPKH or
  P2WSH, with `p2sh-segwit`). Like Core, the top level no longer includes
  `hex`.
- **`generate*` rejects a block count outside a 32-bit int.** The count was
  cut to 32 bits, so `4294967297` mined one block. As in Core, a count
  outside i32 or with a fraction is `-1 JSON integer out of range`, and a
  count of zero or below mines nothing.
- **`estimaterawfee` rejects a threshold outside 0 to 1** with
  `-8 Invalid threshold`, as in Core.
- **`prioritisetransaction` answers a wrong argument count with its help**,
  as Core does, and `dummy` may be `0.0` or null.
- **`submitpackage` admits a parent beside one over `maxfeerate`.** A member
  over the cap blocked the whole package and labelled the other members
  `bad-txns-inputs-missingorspent`. As in Core, the other members are still
  tried, and only those that spend the refused one are missing inputs. With
  `RBITCOIN_RPC_PACKAGE_DIALECT`, a package whose parents spend each other
  is `-25` with Core's message.
- **Raw transactions and blocks decode as in Core.** A null transaction
  decodes, a flag-1 transaction with an empty vin is refused, and an
  output-only transaction decodes only where the legacy form is tried.
  `submitblock` and proposals ignore bytes after the last transaction,
  decode errors carry Core's text, and a base58 address may have whitespace
  around it.
- **A deprioritised parent is mined with the child that pays for it.** A
  negative `prioritisetransaction` delta let a cheap sibling go first, so
  parent, child and sibling shared one diluted chunk that `-blockmintxfee`
  could drop from `getblocktemplate` and `generate`. Clusters are now
  linearized by ancestor-set feerate, as in Core.
- **Chunk feerates match Core's linearization.** Clusters run Core's
  `PostLinearize` and chunking rule, and equal-feerate transactions stay
  separate chunks. The remaining gap is in COMPAT.md.
- **`savemempool` and `importmempool`.** `savemempool` writes Core's version
  2 `{datadir}/mempool.dat`. `importmempool` loads a Core version 1 or 2
  file through normal admission and honors `use_current_time`,
  `apply_fee_delta_priority` and `apply_unbroadcast_set`.
