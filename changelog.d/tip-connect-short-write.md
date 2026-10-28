Fixed

- A store write that fails while connecting a block no longer leaves body
  bytes ahead of the output locators. `gettxout` does not return another
  output's value or script, the block is not marked invalid, and a later
  connect of that block succeeds once writes work. A real consensus failure
  is still kept in `store/block.invalid`.
