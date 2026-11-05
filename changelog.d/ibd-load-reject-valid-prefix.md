Fixed

- **IBD connects the valid blocks below a bad block.** When load rejected a
  block while earlier batches were still in scripts or write, those batches
  were dropped. With one peer their bodies were never asked for again, so the
  tip stopped below its valid prefix and stayed there. Load now lets those
  batches finish before it judges the block, so IBD ends on the bad block's
  parent, as Core does, and fetches nothing again
  ([#1336](https://github.com/rbitcoin-org/rbitcoin/issues/1336)).
