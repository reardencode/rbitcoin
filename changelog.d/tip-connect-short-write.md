Fixed

- A store write that fails while connecting a block no longer leaves body
  bytes ahead of the output locators. `gettxout` does not return another
  output's value or script, the block is not marked invalid, and a later
  connect of that block succeeds once writes work. A crash that leaves a
  locator ahead of its body, or a checkpoint file short of the locator,
  reopens at the last create those files still name. A missed overflow
  header is retried before a later block publishes. A create whose overflow
  row is not in that header is dropped on open. A withheld Class A header
  does not publish `spend_durable` at the new tip. Open drops confirmed
  blocks whose outputs are no longer in that prefix, including blocks
  below the checkblocks window. A confirmed tip whose `header_txs` anchor
  was cleared before that drop is not left in place. Removing `class_a_cut`
  syncs the store directory before open returns, so a later tip flush cannot
  revive that cut. A real consensus failure
  is still kept in `store/block.invalid`.
