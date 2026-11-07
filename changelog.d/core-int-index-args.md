Fixed

- **`gettxout` and `waitforblockheight` reject an out-of-range number, as
  in Core.** Both cut their argument to 32 bits, so `gettxout <txid>
  4294967296` looked up output 0 and `waitforblockheight 4294967297` waited
  for height 1. As in Core, `gettxout` `n` outside 0 to 4294967295 and a
  `waitforblockheight` height outside i32 are `-1 JSON integer out of
  range`, a non-number is `-3`, and a negative height returns the tip at
  once.
