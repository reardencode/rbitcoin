Fixed

- **Electrum: an unused scripthash has status `null`, not `""`.**
  `blockchain.scripthash.subscribe` answered `""` for a script with no
  history, and a push for a script whose history emptied (an RBF victim)
  sent `""` too. The protocol says `null`, and wallets read any non-null
  status as a used address: Sparrow kept deriving past its gap limit
  (`../0/2542` on a wallet whose last used index is far lower) and filled
  the per-connection subscription cap. The subscribe reply and both
  notification paths now send `null`, and a subscribe that answered `null`
  still deduplicates a later push that is still empty.
