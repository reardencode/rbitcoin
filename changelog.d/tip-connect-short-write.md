Fixed

- A store write that fails while connecting a block no longer leaves body
  bytes ahead of the output locators. `gettxout` does not return another
  output's value or script, the block is not marked invalid, and a later
  connect of that block succeeds once writes work. A crash that leaves a
  locator ahead of its body, or a checkpoint file short of the locator,
  reopens at the last create those files still name. A missed overflow
  header is retried before a later block publishes. A create whose overflow
  row is not in that header is dropped on open. A withheld locator header
  does not seal the new tip and does not publish `spend_durable` there.
  Open truncates a body header that ran ahead of that count. A body header
  short of the locator count is corrupt. A real consensus failure
  is still kept in `store/block.invalid`.
