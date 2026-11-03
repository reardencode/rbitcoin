Changed

- **Store-free RPC calls do not take a disk permit.** `getblockcount` and the other methods that never read the store finish while every `--store-read-budget` permit is held. A batch takes one permit only when some call in it reads the store.
- **Template selection does not hold a disk permit.** `getblocktemplate` and Esplora `GET /block-template` keep one permit for the tip confirm and the header reads, then drop it before choosing transactions. The 15-second Esplora cache is not locked across that selection.
