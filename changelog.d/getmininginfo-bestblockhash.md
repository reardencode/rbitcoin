Changed

- **`getmininginfo` names its tip and the next block's work.** It returns
  `bestblockhash` from the same tip read as `blocks` and `bits`
  (bitcoin/bitcoin#36081). `next` now has the bits, target, and difficulty
  the next block must meet, as in getblocktemplate, not the tip's.
  `currentblockweight` and `currentblocktx` describe the last block a
  template, `generate`, or `generateblock` assembled, not a fixed empty
  block. `difficulty`, `next.difficulty`, and `networkhashps` print at
  Core's 16 significant digits.
